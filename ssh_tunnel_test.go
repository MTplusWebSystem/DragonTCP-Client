package main

import (
	"net"
	"testing"
	"time"

	"dragontcp/internal/protocol"
)

func TestSSHTunnelManagerStoresTCPBuffer(t *testing.T) {
	mgr, err := newSSHTunnelManager(nil, "user", "pass", "dragontcp-ssh.internal", 2222, "", "dragontcp-udpgw.internal", 7400, 262144)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr.tcpBuffer != 262144 {
		t.Fatalf("expected tcpBuffer 262144, got %d", mgr.tcpBuffer)
	}
}

func TestTuneTCPAndBufferOnRealSocketAndCarrier(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		serverConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer serverConn.Close()
		protocol.TuneTCP(serverConn)
		protocol.TuneTCPBuffer(serverConn, 131072)
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer clientConn.Close()

	protocol.TuneTCP(clientConn)
	protocol.TuneTCPBuffer(clientConn, 131072)

	// Wrap in carrierConn and test that TuneTCP and TuneTCPBuffer work through unwrapping
	carrier := newSSHCarrierConn(clientConn, 32*1024, 64*1024, time.Millisecond)
	defer carrier.Close()

	protocol.TuneTCP(carrier)
	protocol.TuneTCPBuffer(carrier, 65536)

	// Verify carrier exposes NetConn and socket option methods
	if sc, ok := carrier.(interface{ NetConn() net.Conn }); !ok || sc.NetConn() == nil {
		t.Fatalf("expected carrier to implement NetConn()")
	}

	if noDelaySetter, ok := carrier.(interface{ SetNoDelay(bool) error }); !ok {
		t.Fatalf("expected carrier to implement SetNoDelay()")
	} else if err := noDelaySetter.SetNoDelay(true); err != nil {
		t.Fatalf("SetNoDelay returned error: %v", err)
	}

	if bufSetter, ok := carrier.(interface{ SetReadBuffer(int) error }); !ok {
		t.Fatalf("expected carrier to implement SetReadBuffer()")
	} else if err := bufSetter.SetReadBuffer(65536); err != nil {
		t.Fatalf("SetReadBuffer returned error: %v", err)
	}

	<-done
}
