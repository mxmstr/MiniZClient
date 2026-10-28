package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"testing"
)

func TestDS3RedirectorUsesTLS10(t *testing.T) {
	base := &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12}
	rivals := redirectorTLSConfig(base)
	ds3 := ds3RedirectorTLSConfig(base)
	if rivals.MinVersion != tls.VersionTLS11 || rivals.MaxVersion != tls.VersionTLS11 {
		t.Fatalf("Rivals redirector TLS policy changed: %#x..%#x",
			rivals.MinVersion, rivals.MaxVersion)
	}
	if ds3.MinVersion != tls.VersionTLS10 || ds3.MaxVersion != tls.VersionTLS10 {
		t.Fatalf("DS3 redirector is not pinned to TLS 1.0: %#x..%#x",
			ds3.MinVersion, ds3.MaxVersion)
	}
}

func TestRedirectorAdvertisesLocalBlazeListener(t *testing.T) {
	const correlation = 0x34567
	reply, err := makeRedirectorReply(correlation, "192.168.4.199", 4531)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, actualCorrelation := blazeMetadata(reply)
	if component != 5 || command != 1 || messageType != 1 || actualCorrelation != correlation {
		t.Fatalf("metadata component=%d command=%d type=%d correlation=%#x", component, command, messageType, actualCorrelation)
	}
	decoder := reader{data: reply[12:]}
	fields, err := decoder.fields(false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 || fields[0].Tag != "ADDR" || fields[1].Tag != "SECU" || fields[2].Tag != "XDNS" {
		t.Fatalf("unexpected redirector fields: %#v", fields)
	}
	if fields[1].Value.(int64) != 1 {
		t.Fatalf("redirector endpoint is not marked secure: %#v", fields[1])
	}
	union, ok := fields[0].Value.(Union)
	if !ok || union.Index != 0 || union.Field == nil || union.Field.Tag != "VALU" {
		t.Fatalf("unexpected address union: %#v", fields[0].Value)
	}
	address, ok := union.Field.Value.([]Field)
	if !ok || len(address) != 3 {
		t.Fatalf("unexpected address: %#v", union.Field.Value)
	}
	if string(address[0].Value.([]byte)) != "192.168.4.199" || address[1].Value.(int64) != 0xc0a804c7 || address[2].Value.(int64) != 4531 {
		t.Fatalf("unexpected endpoint: %#v", address)
	}
}

func TestRedirectorReplyPreservesFireFrameContext(t *testing.T) {
	request := make([]byte, 18)
	request[2], request[3] = 0, 5
	request[4], request[5] = 0, 1
	request[8] = 0x07 // request, user index 7
	request[9] = 0x20 // small context
	setBlazeCorrelation(request, 0x54321)
	copy(request[12:], []byte{0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb})

	reply, err := makeDS3RedirectorReplyForRequest(request, 4531)
	if err != nil {
		t.Fatal(err)
	}
	if reply[8] != 0x17 {
		t.Fatalf("message type/user index not preserved: %#x", reply[8])
	}
	if reply[9] != 0x25 || reply[10] != 0x43 || reply[11] != 0x21 {
		t.Fatalf("options/correlation not preserved: %x", reply[9:12])
	}
	if got := reply[12:16]; !bytes.Equal(got, []byte{0x11, 0x22, 0x33, 0x44}) {
		t.Fatalf("context not preserved: %x", got)
	}
	decoder := reader{data: reply[16:]}
	fields, err := decoder.fields(false, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantTags := []string{"ADDR", "SECU", "XDNS"}
	if len(fields) != len(wantTags) {
		t.Fatalf("unexpected DS3 redirector field count: %#v", fields)
	}
	for i, want := range wantTags {
		if fields[i].Tag != want {
			t.Fatalf("DS3 redirector field %d = %q, want %q", i, fields[i].Tag, want)
		}
	}
	addressUnion := fields[0].Value.(Union)
	address := addressUnion.Field.Value.([]Field)
	if string(address[0].Value.([]byte)) != "localhost" || address[1].Value.(int64) != 0x7f000001 || address[2].Value.(int64) != 4531 {
		t.Fatalf("unexpected DS3 endpoint: %#v", address)
	}
	if fields[1].Value.(int64) != 0 || fields[2].Value.(int64) != 0 {
		t.Fatalf("DS3 redirector flags are not zero: %#v", fields[1:])
	}
}

func TestNFS13RedirectorAdvertisesSecureSSL3BlazeEndpoint(t *testing.T) {
	request := make([]byte, 12)
	request[2], request[3] = 0, 5
	request[4], request[5] = 0, 1
	setBlazeCorrelation(request, 0x45678)

	reply, err := makeNFS13RedirectorReplyForRequest(request, "192.168.4.199", 4531)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 5 || command != 1 || messageType != 1 || correlation != 0x45678 {
		t.Fatalf("metadata component=%d command=%d type=%d correlation=%#x",
			component, command, messageType, correlation)
	}
	decoder := reader{data: reply[12:]}
	fields, err := decoder.fields(false, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantTags := []string{"ADDR", "AMAP", "CERT", "MSGS", "NMAP", "SECU", "XDNS"}
	if len(fields) != len(wantTags) {
		t.Fatalf("unexpected NFS13 redirector fields: %#v", fields)
	}
	for i, want := range wantTags {
		if fields[i].Tag != want {
			t.Fatalf("NFS13 redirector field %d = %q, want %q", i, fields[i].Tag, want)
		}
	}
	address := fields[0].Value.(Union).Field.Value.([]Field)
	if string(address[0].Value.([]byte)) != "192.168.4.199" ||
		address[1].Value.(int64) != 0xc0a804c7 || address[2].Value.(int64) != 4531 {
		t.Fatalf("unexpected NFS13 endpoint: %#v", address)
	}
	if fields[5].Value.(int64) != 1 || fields[6].Value.(int64) != 0 {
		t.Fatalf("unexpected NFS13 redirector flags: %#v", fields[5:])
	}
}

func TestDS3RedirectorMatchesCapturedZClientFrame(t *testing.T) {
	request := make([]byte, 12)
	request[2], request[3] = 0, 5
	request[4], request[5] = 0, 1
	// The captured real-ZClient run allocated 48482 as its ephemeral local
	// Blaze proxy port. Supplying that port must reproduce its frame exactly;
	// the standalone backend supplies its fixed port 4531 at runtime.
	reply, err := makeDS3RedirectorReplyForRequest(request, 48482)
	if err != nil {
		t.Fatal(err)
	}
	const captured = "0033000500010000100000008649320600da1b3503a2fcf4010a6c6f63616c686f737400a7000000818080f00fc2fcb400a2f50500ce58f50000e24bb30000"
	if got := hex.EncodeToString(reply); got != captured {
		t.Fatalf("DS3 redirector reply differs from ZClient capture:\n got %s\nwant %s", got, captured)
	}
}
