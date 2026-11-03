package main

import (
	"net"
	"testing"
	"time"
)

func assertNFS13ResetResponseMatchesLiveSetup(t *testing.T, request []byte) {
	t.Helper()
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	server.nfs13 = true
	server.registry = newRegistry(time.Minute, false, false)
	client, peer := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	go server.handle(peer)
	if _, err := client.Write(server.corpus[2].request); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err := readBlazeFrame(client); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply, err := readBlazeFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	c, cmd, kind, corr := blazeMetadata(reply)
	_, _, _, wantCorr := blazeMetadata(request)
	if c != 4 || cmd != 25 || kind != 1 || corr != wantCorr {
		t.Fatal("reset response must precede setup and match request")
	}
	p, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	id, err := integerField(p.Fields, "GID")
	if err != nil || id <= 0 {
		t.Fatalf("missing reset response game ID: %d %v", id, err)
	}
	setup, err := readBlazeFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	c, cmd, kind, corr = blazeMetadata(setup)
	if c != 4 || cmd != 20 || kind != 2 || corr != 0 {
		t.Fatal("expected setup notification after reset response")
	}
	p, err = decodePacket(setup)
	if err != nil {
		t.Fatal(err)
	}
	game, err := structField(p.Fields, "GAME")
	if err != nil {
		t.Fatal(err)
	}
	setupID, err := integerField(game, "GID")
	if err != nil || setupID != id || id != 65536 {
		t.Fatalf("RPC GID=%d setup GID=%d; expected allocated 65536: %v", id, setupID, err)
	}
}
