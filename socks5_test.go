package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func TestUDPGWFrameRoundTripShape(t *testing.T) {
	ip := [4]byte{1, 2, 3, 4}
	data := []byte("dragon")
	frame := buildUDPGWRequest(7, 0, ip, 5353, data)
	payload, err := readUDPGWFrame(bufio.NewReader(bytes.NewReader(frame)))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(payload[0:2]); got != 7 {
		t.Fatalf("conn id=%d", got)
	}
	if !bytes.Equal(payload[3:7], ip[:]) {
		t.Fatalf("ip=%v", payload[3:7])
	}
	if got := binary.BigEndian.Uint16(payload[7:9]); got != 5353 {
		t.Fatalf("port=%d", got)
	}
	if !bytes.Equal(payload[9:], data) {
		t.Fatalf("data=%q", payload[9:])
	}
}

func TestParseSOCKSUDPDatagramIPv4(t *testing.T) {
	packet := []byte{0, 0, 0, socksAtypIPv4, 8, 8, 8, 8, 0, 53, 1, 2, 3}
	ip, port, data, err := parseSOCKSUDPDatagram(packet)
	if err != nil {
		t.Fatal(err)
	}
	if ip != [4]byte{8, 8, 8, 8} {
		t.Fatalf("ip=%v", ip)
	}
	if port != 53 {
		t.Fatalf("port=%d", port)
	}
	if !bytes.Equal(data, []byte{1, 2, 3}) {
		t.Fatalf("data=%v", data)
	}
}

func TestParseSOCKSUDPDatagramRejectsDomainToAvoidDNSLeak(t *testing.T) {
	packet := []byte{0, 0, 0, socksAtypDomain, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 53, 1}
	_, _, _, err := parseSOCKSUDPDatagram(packet)
	if err == nil {
		t.Fatal("expected domain-form UDP destination to be rejected")
	}
}

func TestSOCKSReadRequestAllowsZeroPortForUDPAssociate(t *testing.T) {
	request := []byte{5, socksCmdUDPAssociate, 0, socksAtypIPv4, 0, 0, 0, 0, 0, 0}
	cmd, host, port, err := socksReadRequest(bufio.NewReader(bytes.NewReader(request)))
	if err != nil {
		t.Fatal(err)
	}
	if cmd != socksCmdUDPAssociate || host != "0.0.0.0" || port != 0 {
		t.Fatalf("got cmd=%d host=%q port=%d", cmd, host, port)
	}
}
