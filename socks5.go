package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"dragontcp/internal/protocol"
)

const (
	socksVersion5        = 5
	socksCmdConnect      = 1
	socksCmdUDPAssociate = 3
	socksAtypIPv4        = 1
	socksAtypDomain      = 3
	socksAtypIPv6        = 4
)

func startSOCKS5Proxy(listenAddr string, manager *sshTunnelManager, maxConnections int, tcpBuffer int) (net.Listener, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	if maxConnections < 1 {
		maxConnections = 1
	}
	slots := make(chan struct{}, maxConnections)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func(c net.Conn) {
					defer func() { <-slots; _ = c.Close() }()
					protocol.TuneTCP(c)
					protocol.TuneTCPBuffer(c, tcpBuffer)
					_ = handleSOCKS5(c, manager)
				}(conn)
			default:
				_ = conn.Close()
			}
		}
	}()
	return ln, nil
}

func handleSOCKS5(conn net.Conn, manager *sshTunnelManager) error {
	br := bufio.NewReaderSize(conn, 4096)
	if err := socksNegotiate(br, conn); err != nil {
		return err
	}
	cmd, host, port, err := socksReadRequest(br)
	if err != nil {
		_ = socksReply(conn, 1, nil)
		return err
	}
	switch cmd {
	case socksCmdConnect:
		remote, err := manager.DialTCP(host, port)
		if err != nil {
			_ = socksReply(conn, 5, nil)
			return err
		}
		defer remote.Close()
		if err := socksReply(conn, 0, remote.LocalAddr()); err != nil {
			return err
		}
		protocol.RelayRaw(conn, remote)
		return nil
	case socksCmdUDPAssociate:
		return handleSOCKSUDPAssociate(conn, br, manager)
	default:
		_ = socksReply(conn, 7, nil)
		return fmt.Errorf("SOCKS command %d unsupported", cmd)
	}
}

func socksNegotiate(br *bufio.Reader, w io.Writer) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return err
	}
	if header[0] != socksVersion5 || header[1] == 0 {
		return errors.New("invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	noAuth := false
	for _, method := range methods {
		if method == 0 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = w.Write([]byte{5, 0xff})
		return errors.New("SOCKS5 client does not support no-auth")
	}
	_, err := w.Write([]byte{5, 0})
	return err
}

func socksReadRequest(br *bufio.Reader) (cmd byte, host string, port int, err error) {
	header := make([]byte, 4)
	if _, err = io.ReadFull(br, header); err != nil {
		return
	}
	if header[0] != 5 || header[2] != 0 {
		err = errors.New("invalid SOCKS5 request")
		return
	}
	cmd = header[1]
	host, err = socksReadHost(br, header[3])
	if err != nil {
		return
	}
	var portBuf [2]byte
	if _, err = io.ReadFull(br, portBuf[:]); err != nil {
		return
	}
	port = int(binary.BigEndian.Uint16(portBuf[:]))
	// CONNECT requires a real destination port. UDP ASSOCIATE commonly uses
	// 0.0.0.0:0 to ask the proxy to choose the relay endpoint, which is exactly
	// what the Android VPN adapter sends.
	if cmd == socksCmdConnect && port < 1 {
		err = errors.New("invalid SOCKS5 port")
	}
	return
}

func socksReadHost(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case socksAtypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case socksAtypDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		if n[0] == 0 {
			return "", errors.New("empty SOCKS domain")
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("unsupported SOCKS address type %d", atyp)
	}
}

func socksReply(w io.Writer, rep byte, addr net.Addr) error {
	ip := net.IPv4zero
	port := 0
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		if v4 := tcpAddr.IP.To4(); v4 != nil {
			ip = v4
		}
		port = tcpAddr.Port
	} else if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if v4 := udpAddr.IP.To4(); v4 != nil {
			ip = v4
		}
		port = udpAddr.Port
	}
	out := []byte{5, rep, 0, socksAtypIPv4, 0, 0, 0, 0, 0, 0}
	copy(out[4:8], ip.To4())
	binary.BigEndian.PutUint16(out[8:10], uint16(port))
	_, err := w.Write(out)
	return err
}

func handleSOCKSUDPAssociate(control net.Conn, br *bufio.Reader, manager *sshTunnelManager) error {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return err
	}
	defer udp.Close()
	if err := socksReply(control, 0, udp.LocalAddr()); err != nil {
		return err
	}

	gw, err := manager.DialUDPGW()
	if err != nil {
		return err
	}
	defer gw.Close()
	_ = gw.SetDeadline(time.Time{})

	done := make(chan struct{})
	var closeOnce sync.Once
	closeAll := func() { closeOnce.Do(func() { close(done); _ = udp.Close(); _ = gw.Close() }) }
	defer closeAll()

	var clientMu sync.RWMutex
	var clientAddr *net.UDPAddr
	writeMu := sync.Mutex{}

	go func() {
		defer closeAll()
		reader := bufio.NewReaderSize(gw, 32*1024)
		for {
			payload, err := readUDPGWFrame(reader)
			if err != nil {
				return
			}
			if len(payload) < 9 {
				continue
			}
			srcIP := payload[3:7]
			srcPort := binary.BigEndian.Uint16(payload[7:9])
			data := payload[9:]
			packet := make([]byte, 10+len(data))
			packet[0], packet[1], packet[2], packet[3] = 0, 0, 0, socksAtypIPv4
			copy(packet[4:8], srcIP)
			binary.BigEndian.PutUint16(packet[8:10], srcPort)
			copy(packet[10:], data)
			clientMu.RLock()
			to := clientAddr
			clientMu.RUnlock()
			if to != nil {
				_, _ = udp.WriteToUDP(packet, to)
			}
		}
	}()

	go func() {
		defer closeAll()
		// The UDP association lifetime is the TCP control connection lifetime.
		buf := make([]byte, 1)
		for {
			if _, err := br.Read(buf); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, from, err := udp.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		clientMu.Lock()
		clientAddr = from
		clientMu.Unlock()
		ip, port, payload, err := parseSOCKSUDPDatagram(buf[:n])
		if err != nil {
			continue
		}
		frame := buildUDPGWRequest(1, 0, ip, uint16(port), payload)
		writeMu.Lock()
		_, err = gw.Write(frame)
		writeMu.Unlock()
		if err != nil {
			return err
		}
		select {
		case <-done:
			return nil
		default:
		}
	}
}

func parseSOCKSUDPDatagram(packet []byte) ([4]byte, int, []byte, error) {
	var out [4]byte
	if len(packet) < 10 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return out, 0, nil, errors.New("invalid SOCKS5 UDP packet")
	}
	pos := 3
	atyp := packet[pos]
	pos++
	switch atyp {
	case socksAtypIPv4:
		if len(packet) < pos+4+2 {
			return out, 0, nil, io.ErrUnexpectedEOF
		}
		copy(out[:], packet[pos:pos+4])
		pos += 4
	case socksAtypDomain:
		if len(packet) <= pos {
			return out, 0, nil, io.ErrUnexpectedEOF
		}
		n := int(packet[pos])
		pos++
		if len(packet) < pos+n+2 {
			return out, 0, nil, io.ErrUnexpectedEOF
		}
		return out, 0, nil, errors.New("SOCKS UDP domain destinations are disabled to avoid local DNS leakage; use an IPv4 destination")
	case socksAtypIPv6:
		return out, 0, nil, errors.New("UDPGW supports IPv4 only")
	default:
		return out, 0, nil, errors.New("unsupported SOCKS UDP address type")
	}
	port := int(binary.BigEndian.Uint16(packet[pos : pos+2]))
	pos += 2
	return out, port, packet[pos:], nil
}

func buildUDPGWRequest(connID uint16, x byte, ip [4]byte, port uint16, data []byte) []byte {
	payloadLen := 9 + len(data)
	frame := make([]byte, 2+payloadLen)
	binary.LittleEndian.PutUint16(frame[0:2], uint16(payloadLen))
	binary.BigEndian.PutUint16(frame[2:4], connID)
	frame[4] = x
	copy(frame[5:9], ip[:])
	binary.BigEndian.PutUint16(frame[9:11], port)
	copy(frame[11:], data)
	return frame
}

func readUDPGWFrame(r *bufio.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint16(lenBuf[:]))
	if n < 9 || n > 65535 {
		return nil, fmt.Errorf("invalid UDPGW frame %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
