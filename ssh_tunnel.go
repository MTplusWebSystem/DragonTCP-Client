package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshTunnelManager struct {
	wires        *wireSelector
	username     string
	password     string
	internalHost string
	internalPort int
	pinFile      string
	udpgwHost    string
	udpgwPort    int

	mu     sync.Mutex
	client *ssh.Client
	closed bool

	firstTCPLogged atomic.Bool
	udpLogged      atomic.Bool
}

func newSSHTunnelManager(wires *wireSelector, username, password, internalHost string, internalPort int, pinFile, udpgwHost string, udpgwPort int) (*sshTunnelManager, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("SSH username is required")
	}
	if password == "" {
		return nil, errors.New("SSH password is required")
	}
	if internalHost == "" {
		internalHost = defaultSSHInternalHostClient
	}
	if internalPort < 1 || internalPort > 65535 {
		return nil, errors.New("invalid SSH internal port")
	}
	if udpgwHost == "" {
		udpgwHost = "dragontcp-udpgw.internal"
	}
	if udpgwPort < 1 || udpgwPort > 65535 {
		return nil, errors.New("invalid UDPGW port")
	}
	return &sshTunnelManager{
		wires: wires, username: username, password: password,
		internalHost: internalHost, internalPort: internalPort,
		pinFile: pinFile, udpgwHost: udpgwHost, udpgwPort: udpgwPort,
	}, nil
}

const (
	defaultSSHInternalHostClient = "dragontcp-ssh.internal"
	sshCarrierWriteBatch         = 1024 * 1024
	sshCarrierMaxBuffered        = 4 * 1024 * 1024
	sshCarrierFlushDelay         = 2 * time.Millisecond
)

func (m *sshTunnelManager) hostKeyCallback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		if strings.TrimSpace(m.pinFile) == "" {
			return nil
		}
		data, err := os.ReadFile(m.pinFile)
		if err == nil {
			expected := strings.TrimSpace(string(data))
			if expected == fingerprint {
				return nil
			}
			return fmt.Errorf("SSH host key changed: expected %s got %s", expected, fingerprint)
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("read SSH host key pin: %w", err)
		}
		if err := os.WriteFile(m.pinFile, []byte(fingerprint+"\n"), 0600); err != nil {
			return fmt.Errorf("save SSH host key pin: %w", err)
		}
		fmt.Printf("ssh host key pinned: %s\n", fingerprint)
		return nil
	}
}

func (m *sshTunnelManager) connectLocked() (*ssh.Client, error) {
	if m.closed {
		return nil, net.ErrClosed
	}
	if m.client != nil {
		return m.client, nil
	}

	fmt.Printf("ssh carrier: opening DragonTCP stream to %s:%d\n", m.internalHost, m.internalPort)
	transport, err := m.wires.dial(m.internalHost, m.internalPort)
	if err != nil {
		return nil, fmt.Errorf("DragonTCP SSH carrier failed: %w", err)
	}
	// SSH emits encrypted packets in ~tens-of-KiB writes. Feeding each one
	// directly into the transactional DragonTCP transport creates a full RTT per
	// SSH packet. Combine them behind bounded backpressure so a busy SSH stream
	// reaches DragonTCP's discovered 256 KiB-1 MiB chunk sizes instead.
	transport = newSSHCarrierConn(transport, sshCarrierWriteBatch, sshCarrierMaxBuffered, sshCarrierFlushDelay)
	fmt.Printf("ssh carrier: DragonTCP stream connected write_batch=%d max_buffer=%d flush_delay=%s\n", sshCarrierWriteBatch, sshCarrierMaxBuffered, sshCarrierFlushDelay)
	cfg := &ssh.ClientConfig{
		User:            m.username,
		Auth:            []ssh.AuthMethod{ssh.Password(m.password)},
		HostKeyCallback: m.hostKeyCallback(),
		ClientVersion:   "SSH-2.0-DragonTCP",
	}
	addr := net.JoinHostPort(m.internalHost, fmt.Sprintf("%d", m.internalPort))
	cc, chans, reqs, err := ssh.NewClientConn(transport, addr, cfg)
	if err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("SSH handshake/auth failed: %w", err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	m.client = client
	fmt.Printf("ssh authenticated: user=%s transport=DragonTCP mode=tunnel-only\n", m.username)
	go m.keepalive(client)
	return client, nil
}

func (m *sshTunnelManager) getClient() (*ssh.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connectLocked()
}

func (m *sshTunnelManager) invalidate(client *ssh.Client) {
	m.mu.Lock()
	if m.client == client {
		m.client = nil
		_ = client.Close()
	}
	m.mu.Unlock()
}

func (m *sshTunnelManager) keepalive(client *ssh.Client) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		_, _, err := client.SendRequest("keepalive@dragontcp", true, nil)
		if err != nil {
			m.invalidate(client)
			return
		}
		m.mu.Lock()
		same := m.client == client && !m.closed
		m.mu.Unlock()
		if !same {
			return
		}
	}
}

func (m *sshTunnelManager) Warmup() error {
	_, err := m.getClient()
	return err
}

func (m *sshTunnelManager) DialTCP(host string, port int) (net.Conn, error) {
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		client, err := m.getClient()
		if err != nil {
			// Authentication, handshake, or physical-carrier failures are hard
			// boundaries. Retrying them immediately would duplicate expensive
			// DragonTCP/SSH connection attempts and can overload the server.
			return nil, err
		}
		conn, err := client.Dial("tcp", target)
		if err == nil {
			if m.firstTCPLogged.CompareAndSwap(false, true) {
				fmt.Printf("ssh traffic: direct-tcpip active\n")
			}
			return conn, nil
		}
		lastErr = err
		// A direct-tcpip channel rejection means the SSH transport is healthy
		// and only this destination failed (for example ECONNREFUSED or a
		// server-side target-policy rejection). Do not tear down the persistent
		// SSH carrier or redial the destination in that case.
		var openErr *ssh.OpenChannelError
		if errors.As(err, &openErr) {
			return nil, err
		}
		m.invalidate(client)
	}
	if lastErr == nil {
		lastErr = errors.New("SSH target dial failed")
	}
	return nil, lastErr
}

func (m *sshTunnelManager) DialUDPGW() (net.Conn, error) {
	conn, err := m.DialTCP(m.udpgwHost, m.udpgwPort)
	if err == nil && m.udpLogged.CompareAndSwap(false, true) {
		fmt.Printf("ssh traffic: UDPGW active target=%s:%d\n", m.udpgwHost, m.udpgwPort)
	}
	return conn, err
}

func (m *sshTunnelManager) Close() error {
	m.mu.Lock()
	m.closed = true
	client := m.client
	m.client = nil
	m.mu.Unlock()
	if client != nil {
		return client.Close()
	}
	return nil
}
