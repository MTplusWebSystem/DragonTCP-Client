package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"dragontcp/internal/protocol"
	"dragontcp/internal/xorchunk"
)

const maxHeader = 128 * 1024

var requestCounter atomic.Uint32

func readHTTPHeaders(conn net.Conn) ([]byte, []byte, error) {
	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 8192)

	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)

			if len(buf) > maxHeader {
				return nil, nil, fmt.Errorf("HTTP headers too large")
			}

			if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
				end := i + 4
				return buf[:end], buf[end:], nil
			}
		}

		if err != nil {
			return nil, nil, err
		}
	}
}

func parseHostPort(authority string, defaultPort int) (string, int, error) {
	authority = strings.TrimSpace(authority)

	if host, portText, err := net.SplitHostPort(authority); err == nil {
		port, err := strconv.Atoi(portText)
		return host, port, err
	}

	// Host without port.
	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		return strings.Trim(authority, "[]"), defaultPort, nil
	}

	if strings.Count(authority, ":") == 0 {
		return authority, defaultPort, nil
	}

	// Bare IPv6.
	if ip := net.ParseIP(authority); ip != nil {
		return authority, defaultPort, nil
	}

	return "", 0, fmt.Errorf("invalid authority: %s", authority)
}

func rewritePlainHTTPRequest(header []byte) (string, int, []byte, error) {
	text := string(header)
	lines := strings.Split(text, "\r\n")
	if len(lines) == 0 {
		return "", 0, nil, fmt.Errorf("empty request")
	}

	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) != 3 {
		return "", 0, nil, fmt.Errorf("invalid request line")
	}

	method, target, version := parts[0], parts[1], parts[2]

	var (
		hostHeader string
		headers    []string
	)

	for _, line := range lines[1:] {
		if line == "" {
			continue
		}

		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		lk := strings.ToLower(strings.TrimSpace(k))

		if lk == "host" {
			hostHeader = strings.TrimSpace(v)
		}

		if lk == "connection" ||
			lk == "proxy-connection" ||
			lk == "proxy-authorization" {
			continue
		}

		headers = append(headers, k+": "+strings.TrimSpace(v))
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", 0, nil, err
	}

	var host string
	var port int
	path := target

	if u.Hostname() != "" {
		if strings.ToLower(u.Scheme) != "http" {
			return "", 0, nil, fmt.Errorf("unsupported plain HTTP scheme: %s", u.Scheme)
		}

		host = u.Hostname()
		port = 80

		if u.Port() != "" {
			port, err = strconv.Atoi(u.Port())
			if err != nil {
				return "", 0, nil, err
			}
		}

		path = u.EscapedPath()
		if path == "" {
			path = "/"
		}
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
	} else {
		if hostHeader == "" {
			return "", 0, nil, fmt.Errorf("missing Host header")
		}

		host, port, err = parseHostPort(hostHeader, 80)
		if err != nil {
			return "", 0, nil, err
		}
		if path == "" {
			path = "/"
		}
	}

	var out strings.Builder
	fmt.Fprintf(&out, "%s %s %s\r\n", method, path, version)

	sawHost := false
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h), "host:") {
			sawHost = true
		}
		out.WriteString(h)
		out.WriteString("\r\n")
	}

	if !sawHost {
		if port == 80 {
			fmt.Fprintf(&out, "Host: %s\r\n", host)
		} else {
			fmt.Fprintf(&out, "Host: %s\r\n", net.JoinHostPort(host, strconv.Itoa(port)))
		}
	}

	out.WriteString("Connection: close\r\n\r\n")

	return host, port, []byte(out.String()), nil
}

func openDragonTCPTunnel(serverAddr, token, targetHost string, targetPort int, transport string, tcpBuffer int) (net.Conn, error) {
	d := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := d.Dial("tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	protocol.TuneTCP(conn)
	protocol.TuneTCPBuffer(conn, tcpBuffer)
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Correlation only; cryptographic randomness is unnecessary here.
	requestID := requestCounter.Add(1)

	var command []byte
	if transport == "raw" {
		command = []byte(fmt.Sprintf("TUNNEL2 %s %s %d RAW", token, targetHost, targetPort))
	} else {
		// Legacy XOR command remains compatible with the older server.
		command = []byte(fmt.Sprintf("TUNNEL %s %s %d", token, targetHost, targetPort))
	}

	if err := protocol.WriteRequestFrame(conn, requestID, command); err != nil {
		conn.Close()
		return nil, err
	}

	responseID, response, err := protocol.ReadResponseFrame(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if responseID != requestID {
		conn.Close()
		return nil, fmt.Errorf("request ID mismatch")
	}

	if string(response) != "CONNECTED" {
		conn.Close()
		return nil, fmt.Errorf("%s", response)
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func writeHTTPError(conn net.Conn, code int, reason, detail string) {
	if detail == "" {
		detail = reason
	}

	body := []byte(detail)

	fmt.Fprintf(
		conn,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		code,
		reason,
		len(body),
	)
	_, _ = conn.Write(body)
}

func handleLocal(conn net.Conn, serverAddr, token, transport string, tcpBuffer int, wires *wireSelector, slots chan struct{}) {
	defer func() {
		<-slots
		_ = conn.Close()
	}()

	protocol.TuneTCP(conn)
	protocol.TuneTCPBuffer(conn, tcpBuffer)
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	header, extra, err := readHTTPHeaders(conn)
	if err != nil {
		return
	}

	firstLine := strings.SplitN(string(header), "\r\n", 2)[0]
	parts := strings.SplitN(firstLine, " ", 3)

	if len(parts) != 3 {
		writeHTTPError(conn, 400, "Bad Request", "invalid HTTP request line")
		return
	}

	method, target := parts[0], parts[1]

	if strings.EqualFold(method, "CONNECT") {
		host, port, err := parseHostPort(target, 443)
		if err != nil {
			writeHTTPError(conn, 400, "Bad Request", err.Error())
			return
		}

		var remote net.Conn
		if transport == "chunk" {
			remote, err = wires.dial(host, port)
		} else {
			remote, err = openDragonTCPTunnel(serverAddr, token, host, port, transport, tcpBuffer)
		}
		if err != nil {
			writeHTTPError(conn, 502, "Bad Gateway", err.Error())
			return
		}
		defer remote.Close()

		_, _ = conn.Write([]byte(
			"HTTP/1.1 200 Connection Established\r\n" +
				"Proxy-Agent: dragontcp-proxy/2.0\r\n\r\n",
		))

		if len(extra) > 0 {
			if transport == "xor" {
				protocol.XorInPlace(extra)
			}
			if _, err := remote.Write(extra); err != nil {
				return
			}
		}

		_ = conn.SetDeadline(time.Time{})
		if transport == "xor" {
			protocol.RelayXOR(conn, remote)
		} else {
			// raw and chunk connections expose a normal plaintext net.Conn.
			protocol.RelayRaw(conn, remote)
		}
		return
	}

	host, port, rewritten, err := rewritePlainHTTPRequest(header)
	if err != nil {
		writeHTTPError(conn, 400, "Bad Request", err.Error())
		return
	}

	var remote net.Conn
	if transport == "chunk" {
		remote, err = wires.dial(host, port)
	} else {
		remote, err = openDragonTCPTunnel(serverAddr, token, host, port, transport, tcpBuffer)
	}
	if err != nil {
		writeHTTPError(conn, 502, "Bad Gateway", err.Error())
		return
	}
	defer remote.Close()

	initial := make([]byte, 0, len(rewritten)+len(extra))
	initial = append(initial, rewritten...)
	initial = append(initial, extra...)
	if transport == "xor" {
		protocol.XorInPlace(initial)
	}

	if _, err := remote.Write(initial); err != nil {
		return
	}

	_ = conn.SetDeadline(time.Time{})
	if transport == "xor" {
		protocol.RelayXOR(conn, remote)
	} else {
		protocol.RelayRaw(conn, remote)
	}
}

const serverPortReachabilityTimeout = 900 * time.Millisecond

func serverPortReachable(host string, port int, tcpBuffer int) bool {
	d := net.Dialer{Timeout: serverPortReachabilityTimeout, KeepAlive: 30 * time.Second}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	protocol.TuneTCP(conn)
	protocol.TuneTCPBuffer(conn, tcpBuffer)
	_ = conn.Close()
	return true
}

// selectServerEndpoint walks the user-configured port range in ascending order.
// A port is not considered working merely because the TCP handshake succeeds:
// the normal DragonTCP wire/header probe must also validate on that endpoint.
// Only one port candidate is protocol-tested at a time; UP/DW calibration starts
// only after a single endpoint has been locked.
func selectServerEndpoint(
	host string,
	portStart int,
	portEnd int,
	token string,
	configuredWire string,
	binOpts chunkClientOptions,
	xorOpts xorchunk.Options,
	probeDelay time.Duration,
	probeThreads int,
	forceClear bool,
	tcpBuffer int,
) (*wireSelector, string, int, error) {
	total := portEnd - portStart + 1
	fmt.Printf("[D-TCP] phase=PORT_SCAN state=starting host=%s start=%d end=%d total=%d protocol_validation=true\n", host, portStart, portEnd, total)

	for port := portStart; port <= portEnd; port++ {
		index := port - portStart + 1
		// Keep logs readable for wide ranges: always show the first candidate,
		// every 16th candidate, and every TCP-reachable candidate.
		if index == 1 || index%16 == 0 || port == portEnd {
			fmt.Printf("[D-TCP] phase=PORT_SCAN state=testing candidate=%d progress=%d/%d\n", port, index, total)
		}
		if !serverPortReachable(host, port, tcpBuffer) {
			continue
		}

		addr := net.JoinHostPort(host, strconv.Itoa(port))
		fmt.Printf("[D-TCP] phase=PORT_SCAN state=tcp_reachable candidate=%d progress=%d/%d\n", port, index, total)
		selector := newWireSelector(configuredWire, addr, token, binOpts, xorOpts, probeDelay, probeThreads, forceClear)
		choice, err := selector.resolveOnly()
		if err != nil {
			fmt.Printf("[D-TCP] phase=PORT_SCAN state=rejected candidate=%d reason=no_validated_wire\n", port)
			continue
		}

		fmt.Printf("[D-TCP] phase=PORT_SCAN state=success port=%d wire=%s header_mask=%02x clear_payload=%t\n", port, choice.mode, choice.mask, choice.cover.Clear)
		return selector, addr, port, nil
	}

	fmt.Printf("[D-TCP] phase=PORT_SCAN state=failed start=%d end=%d reason=no_working_dragontcp_port\n", portStart, portEnd)
	return nil, "", 0, fmt.Errorf("no working DragonTCP port found in %d-%d", portStart, portEnd)
}

func main() {
	var (
		listenHost          = flag.String("listen-host", "127.0.0.1", "local proxy listen host")
		listenPort          = flag.Int("listen-port", 8080, "local proxy listen port")
		serverHost          = flag.String("server-host", "", "remote DragonTCP server host")
		serverPort          = flag.Int("server-port", 53, "remote DragonTCP server port; used when no range is supplied")
		serverPortStart     = flag.Int("server-port-start", 0, "first remote DragonTCP port to scan; 0 uses --server-port")
		serverPortEnd       = flag.Int("server-port-end", 0, "last remote DragonTCP port to scan; 0 uses the resolved start port")
		token               = flag.String("token", "", "optional shared token")
		maxConnections      = flag.Int("max-connections", 20000, "max simultaneous proxy connections")
		transport           = flag.String("transport", "chunk", "transport: chunk (DragonTCP binary adaptive transport)")
		tcpBuffer           = flag.Int("tcp-buffer", 0, "optional TCP read/write buffer bytes; 0 keeps OS autotuning")
		chunkStart          = flag.Int("chunk-start", 1048576, "initial adaptive chunk payload bytes")
		chunkMin            = flag.Int("chunk-min", 32, "minimum adaptive chunk payload bytes")
		chunkMax            = flag.Int("chunk-max", 1048576, "maximum adaptive chunk payload bytes (up to 1 MiB)")
		chunkAdaptive       = flag.Bool("chunk-adaptive", true, "automatically shrink on failures and grow after stable success")
		chunkSuccesses      = flag.Int("chunk-grow-after", 16, "successful data records required before increasing chunk size")
		chunkShrinkAfter    = flag.Int("chunk-shrink-after", 1, "consecutive recoverable transfer failures required before reducing chunk size")
		chunkShrinkStep     = flag.Int("chunk-shrink-step", 200, "bytes to subtract on each recoverable runtime chunk failure; Android uses 200")
		chunkMaxFirst       = flag.Bool("chunk-max-first", false, "legacy CLI-only max-first calibration; Android uses ascending calibration")
		chunkAdaptLog       = flag.Bool("chunk-adapt-log", true, "print adaptive chunk size changes")
		chunkSizeLegacy     = flag.Int("chunk-size", 0, "legacy fixed chunk size; nonzero disables adaptation")
		chunkPollers        = flag.Int("chunk-pollers", 1, "reserved compatibility setting; binary transport uses one download worker")
		chunkConcurrency    = flag.Int("chunk-concurrency", 1, "maximum download records per request (1-256)")
		chunkConcurrencyMin = flag.Int("chunk-concurrency-min", 1, "minimum download records per request (1-256); equal to --chunk-concurrency pins the depth")
		chunkReconnect      = flag.Int("chunk-reconnect-every", 0, "connection reuse: 0 persistent, 1 auto-learn, N rotate after N requests")
		chunkPollDelay      = flag.Duration("chunk-poll-delay", 2*time.Millisecond, "delay after an empty chunk poll")
		chunkTimeout        = flag.Duration("chunk-timeout", 5*time.Second, "per-record transaction timeout; a real timeout terminates the tunnel")
		wireMode            = flag.String("wire", "auto", "wire mode: b, bp, x, or auto (probe and pick)")
		forceClearPayload   = flag.Bool("force-clear-payload", false, "force B/BP clear payloads and disable the SHA-256 payload mask; no masked fallback")
		wireProbeDelay      = flag.Duration("wire-probe-delay", 100*time.Millisecond, "minimum delay between header/profile probe starts (50ms-30s)")
		wireProbeThreads    = flag.Int("wire-probe-threads", 1, "maximum concurrent wire profile probes (1-16)")

		sshUser         = flag.String("ssh-user", "", "SSH tunnel username; enables tunnel-only SSH/SOCKS mode")
		sshPassword     = flag.String("ssh-password", "", "SSH tunnel password")
		sshPasswordEnv  = flag.String("ssh-password-env", "", "environment variable containing the SSH tunnel password")
		sshInternalHost = flag.String("ssh-internal-host", defaultSSHInternalHostClient, "reserved DragonTCP target for internal SSH")
		sshInternalPort = flag.Int("ssh-internal-port", 2222, "internal fake SSH port on the DragonTCP server")
		sshHostKeyPin   = flag.String("ssh-hostkey-pin-file", "", "TOFU SSH host-key fingerprint file")
		sshSocksHost    = flag.String("ssh-socks-host", "127.0.0.1", "local SOCKS5 listen host when SSH mode is enabled")
		sshSocksPort    = flag.Int("ssh-socks-port", 1080, "local SOCKS5 listen port when SSH mode is enabled")
		sshUDPGWHost    = flag.String("ssh-udpgw-host", "dragontcp-udpgw.internal", "reserved UDPGW target as seen by the SSH server")
		sshUDPGWPort    = flag.Int("ssh-udpgw-port", 7400, "UDPGW port as seen by the SSH server")
	)
	flag.Parse()
	if strings.TrimSpace(*sshPasswordEnv) != "" {
		*sshPassword = os.Getenv(strings.TrimSpace(*sshPasswordEnv))
	}

	if *serverHost == "" {
		fmt.Fprintln(os.Stderr, "--server-host is required")
		os.Exit(2)
	}
	resolvedPortStart := *serverPortStart
	resolvedPortEnd := *serverPortEnd
	if resolvedPortStart == 0 {
		resolvedPortStart = *serverPort
	}
	if resolvedPortEnd == 0 {
		resolvedPortEnd = resolvedPortStart
	}
	if resolvedPortStart < 1 || resolvedPortStart > 65535 || resolvedPortEnd < 1 || resolvedPortEnd > 65535 {
		fmt.Fprintln(os.Stderr, "server ports must be between 1 and 65535")
		os.Exit(2)
	}
	if resolvedPortStart > resolvedPortEnd {
		fmt.Fprintln(os.Stderr, "--server-port-start must not exceed --server-port-end")
		os.Exit(2)
	}

	*transport = strings.ToLower(*transport)
	if *transport != "chunk" {
		fmt.Fprintln(os.Stderr, "DragonTCP requires --transport chunk (binary adaptive TCP/53 transport)")
		os.Exit(2)
	}
	if *chunkSizeLegacy != 0 {
		if *chunkSizeLegacy < 32 || *chunkSizeLegacy > protocol.MaxChunkPayload {
			fmt.Fprintf(os.Stderr, "--chunk-size must be between 32 and %d\n", protocol.MaxChunkPayload)
			os.Exit(2)
		}
		*chunkStart = *chunkSizeLegacy
		*chunkMin = *chunkSizeLegacy
		*chunkMax = *chunkSizeLegacy
		*chunkAdaptive = false
	}
	if *chunkMaxFirst {
		// Retained for CLI compatibility only. The Android build never enables
		// this flag; its startup calibration is always ascending.
		*chunkStart = *chunkMax
	}
	if *chunkMin < 32 || *chunkMax > protocol.MaxChunkPayload || *chunkMin > *chunkStart || *chunkStart > *chunkMax {
		fmt.Fprintf(os.Stderr, "require 32 <= --chunk-min <= --chunk-start <= --chunk-max <= %d\n", protocol.MaxChunkPayload)
		os.Exit(2)
	}
	if *chunkSuccesses < 1 {
		fmt.Fprintln(os.Stderr, "--chunk-grow-after must be at least 1")
		os.Exit(2)
	}
	if *chunkShrinkAfter < 1 || *chunkShrinkAfter > 32 {
		fmt.Fprintln(os.Stderr, "--chunk-shrink-after must be between 1 and 32")
		os.Exit(2)
	}
	if *chunkShrinkStep < 0 || *chunkShrinkStep > protocol.MaxChunkPayload {
		fmt.Fprintf(os.Stderr, "--chunk-shrink-step must be between 0 and %d bytes\n", protocol.MaxChunkPayload)
		os.Exit(2)
	}
	if *chunkMaxFirst {
		// MAX-FIRST always uses one recoverable failure as a signal to move
		// to the next calibration candidate. shrinkStep is the final boundary
		// resolution and the runtime linear recovery step.
		if *chunkShrinkStep == 0 {
			*chunkShrinkStep = maxFirstFineResolution
		}
		*chunkShrinkAfter = 1
	}
	if *chunkPollers < 1 || *chunkPollers > 128 {
		fmt.Fprintln(os.Stderr, "--chunk-pollers must be between 1 and 128")
		os.Exit(2)
	}
	if *chunkConcurrency < 1 || *chunkConcurrency > 256 {
		fmt.Fprintln(os.Stderr, "--chunk-concurrency must be between 1 and 256")
		os.Exit(2)
	}
	if *chunkConcurrencyMin < 1 || *chunkConcurrencyMin > 256 {
		fmt.Fprintln(os.Stderr, "--chunk-concurrency-min must be between 1 and 256")
		os.Exit(2)
	}
	if *chunkConcurrencyMin > *chunkConcurrency {
		fmt.Fprintln(os.Stderr, "--chunk-concurrency-min must not exceed --chunk-concurrency")
		os.Exit(2)
	}
	*wireMode = strings.ToLower(strings.TrimSpace(*wireMode))
	switch *wireMode {
	case WireBinary, WireBP, WireXOR, WireAuto:
	case "binary":
		*wireMode = WireBinary
	case "bh", "h":
		*wireMode = WireBP
	case "xor":
		*wireMode = WireXOR
	default:
		fmt.Fprintln(os.Stderr, "--wire must be b, bp, x or auto")
		os.Exit(2)
	}
	if *forceClearPayload && *wireMode == WireXOR {
		fmt.Fprintln(os.Stderr, "--force-clear-payload cannot be used with --wire x; use auto, b, or bp")
		os.Exit(2)
	}
	if *chunkReconnect < 0 {
		fmt.Fprintln(os.Stderr, "--chunk-reconnect-every must be 0 or greater")
		os.Exit(2)
	}
	if *wireProbeDelay < 50*time.Millisecond || *wireProbeDelay > 30*time.Second {
		fmt.Fprintln(os.Stderr, "--wire-probe-delay must be between 50ms and 30s")
		os.Exit(2)
	}
	if *wireProbeThreads < 1 || *wireProbeThreads > 16 {
		fmt.Fprintln(os.Stderr, "--wire-probe-threads must be between 1 and 16")
		os.Exit(2)
	}
	sshEnabled := strings.TrimSpace(*sshUser) != ""
	var err error
	if sshEnabled {
		if *sshPassword == "" {
			fmt.Fprintln(os.Stderr, "--ssh-password is required when --ssh-user is set")
			os.Exit(2)
		}
		if *sshInternalPort < 1 || *sshInternalPort > 65535 || *sshSocksPort < 1 || *sshSocksPort > 65535 || *sshUDPGWPort < 1 || *sshUDPGWPort > 65535 {
			fmt.Fprintln(os.Stderr, "SSH/SOCKS/UDPGW ports must be between 1 and 65535")
			os.Exit(2)
		}
	}
	chunkOpts := chunkClientOptions{
		startSize:      *chunkStart,
		minSize:        *chunkMin,
		maxSize:        *chunkMax,
		adaptive:       *chunkAdaptive,
		adaptSuccesses: *chunkSuccesses,
		shrinkAfter:    *chunkShrinkAfter,
		shrinkStep:     *chunkShrinkStep,
		adaptLog:       *chunkAdaptLog,
		pollers:        *chunkPollers,
		minPipeline:    *chunkConcurrencyMin,
		maxPipeline:    *chunkConcurrency,
		reconnectEvery: *chunkReconnect,
		pollDelay:      *chunkPollDelay,
		txnTimeout:     *chunkTimeout,
		tcpBuffer:      *tcpBuffer,
		forceMaxStart:  *chunkMaxFirst,
	}

	xorOpts := xorchunk.NewOptions(
		*chunkStart, *chunkMin, *chunkMax, *chunkAdaptive, *chunkSuccesses, *chunkShrinkAfter, *chunkAdaptLog,
		*chunkPollers, *chunkReconnect, *chunkPollDelay, *chunkTimeout, *tcpBuffer,
	)

	listenAddr := net.JoinHostPort(*listenHost, strconv.Itoa(*listenPort))

	fmt.Printf("remote DragonTCP host=%s port_range=%d-%d\n", *serverHost, resolvedPortStart, resolvedPortEnd)
	fmt.Printf("max_connections=%d transport=%s tcp_buffer=%d\n", *maxConnections, *transport, *tcpBuffer)
	if *transport == "chunk" {
		batchMode := "adaptive"
		if *chunkConcurrencyMin == *chunkConcurrency {
			batchMode = "pinned"
		}
		fmt.Printf(
			"adaptive_chunk=%v start=%d min=%d max=%d grow_after=%d shrink_after=%d shrink_step=%d max_first=%v pollers=%d batch=%d-%d(%s) reconnect_every=%d timeout=%s\n",
			*chunkAdaptive,
			*chunkStart,
			*chunkMin,
			*chunkMax,
			*chunkSuccesses,
			*chunkShrinkAfter,
			*chunkShrinkStep,
			*chunkMaxFirst,
			*chunkPollers,
			*chunkConcurrencyMin,
			*chunkConcurrency,
			batchMode,
			*chunkReconnect,
			chunkTimeout.String(),
		)
	}

	if *forceClearPayload {
		fmt.Printf("wire=%s force_clear_payload=true payload_sha256=false clear_header_order=00,25 protocol_probe=server-local\n", *wireMode)
	} else {
		fmt.Printf("wire=%s discovering fixed header profile full_range=00-ff protocol_probe=server-local probe_delay=%s probe_threads=%d force_clear_payload=false\n", *wireMode, wireProbeDelay.String(), *wireProbeThreads)
	}

	// Port discovery happens before chunk calibration. A TCP-open port must also
	// pass the DragonTCP wire/header probe before it becomes the WORKING PORT.
	wires, serverAddr, selectedPort, err := selectServerEndpoint(
		*serverHost, resolvedPortStart, resolvedPortEnd, *token, *wireMode,
		chunkOpts, xorOpts, *wireProbeDelay, *wireProbeThreads, *forceClearPayload, *tcpBuffer,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DragonTCP port discovery failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("remote DragonTCP endpoint=%s working_port=%d\n", serverAddr, selectedPort)

	// Resolve/authenticate the already-selected wire and calibrate UP/DW before
	// exposing the local proxy. resolveOnly() cached the profile, so prepare()
	// performs no second header scan.
	if _, err := wires.prepare(); err != nil {
		fmt.Fprintf(os.Stderr, "DragonTCP startup preflight failed: %v\n", err)
		os.Exit(1)
	}

	var sshManager *sshTunnelManager
	var socksListener net.Listener
	if strings.TrimSpace(*sshUser) != "" {
		sshManager, err = newSSHTunnelManager(wires, *sshUser, *sshPassword, *sshInternalHost, *sshInternalPort, *sshHostKeyPin, *sshUDPGWHost, *sshUDPGWPort)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer sshManager.Close()
		// Validate the complete DragonTCP -> SSH path before advertising the
		// local SOCKS endpoint. Previously the Android UI could say "SSH tunnel
		// ready" even though no SSH handshake had happened yet.
		if err = sshManager.Warmup(); err != nil {
			fmt.Fprintf(os.Stderr, "SSH startup failed: %v\n", err)
			os.Exit(1)
		}
		socksAddr := net.JoinHostPort(*sshSocksHost, strconv.Itoa(*sshSocksPort))
		socksListener, err = startSOCKS5Proxy(socksAddr, sshManager, *maxConnections, *tcpBuffer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "SOCKS5 listen failed: %v\n", err)
			os.Exit(1)
		}
		defer socksListener.Close()
		fmt.Printf("ssh_mode=true local_socks5=%s internal_ssh=%s:%d udpgw=%s:%d user=%s\n", socksAddr, *sshInternalHost, *sshInternalPort, *sshUDPGWHost, *sshUDPGWPort, *sshUser)
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer ln.Close()
	fmt.Printf("local Go HTTP proxy listening on %s\n", listenAddr)

	slots := make(chan struct{}, *maxConnections)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "accept:", err)
			continue
		}

		select {
		case slots <- struct{}{}:
			go handleLocal(conn, serverAddr, *token, *transport, *tcpBuffer, wires, slots)
		default:
			writeHTTPError(
				conn,
				503,
				"Service Unavailable",
				"proxy connection limit reached",
			)
			_ = conn.Close()
		}
	}
}
