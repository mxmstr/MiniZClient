package main

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

func TestNFS13RemovePlayerCompletesOnLiveConnection(t *testing.T) {
	// Capture 72592: client leaves immediately after the friends-game setup.
	raw, err := hex.DecodeString("00240004000b00000000002c8b4c2c090000008eed3800009e990000808008c2990000a401ca58730006ce3d38010100")
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer client.Close()
	server := &blazeServer{nfs13: true}
	go server.handle(peer)
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write(raw); err != nil {
		t.Fatal(err)
	}
	ack, err := readBlazeFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	c, cmd, kind, corr := blazeMetadata(ack)
	if c != 4 || cmd != 11 || kind != 1 || corr != 44 {
		t.Fatal("invalid remove acknowledgement")
	}
	removed, err := readBlazeFrame(client)
	if err != nil {
		t.Fatal("missing departure notification", err)
	}
	c, cmd, kind, corr = blazeMetadata(removed)
	if c != 4 || cmd != 40 || kind != 2 || corr != 0 {
		t.Fatal("invalid removal notification")
	}
	packet, err := decodePacket(removed)
	if err != nil {
		t.Fatal(err)
	}
	for tag, want := range map[string]int64{"CNTX": 0, "GID": 65536, "PID": 100, "REAS": 6} {
		value, err := integerField(packet.Fields, tag)
		if err != nil || value != want {
			t.Fatalf("%s=%d want %d: %v", tag, value, want, err)
		}
	}
	// Cleanup must not drop the Autolog transport.
	if _, err := client.Write(statsRequest(t, 4, "license_plate", 52)); err != nil {
		t.Fatal(err)
	}
	if _, err := readBlazeFrame(client); err != nil {
		t.Fatal("transport closed after leave", err)
	}
}

func TestNFS13SessionReadiness(t *testing.T) {
	// Actual user-added and extended-data frames from stalled capture 60184.
	frames := []string{
		"004d78020002000020000000921d210392d8700500000201b407818090800f00d6ccf404090182e00302a40100d739720386990000a40186cbe30093d5f2d60ca6400000a401ba1b650107706c6179657200bf2a6700a40100",
		"007278020001000020000000921d21038649320602da1b3503978a7003a700000080808010b618e90000c2fcb4008b3900a6ea7003a70000008793c08a18b618e90000c2fcb4008b3900b618e900a6f3e29e09008b0cc001047a6c6f0092d8700500000201b407818090800f00c6487403ba1d3400050000d73a6400a401",
	}
	for _, frame := range frames {
		raw, err := hex.DecodeString(frame)
		if err != nil {
			t.Fatal(err)
		}
		got, err := nfs13SessionDataReply(raw)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := decodePacket(got)
		if err != nil {
			t.Fatal(err)
		}
		data, err := structField(packet.Fields, "DATA")
		if err != nil {
			t.Fatal(err)
		}
		field, err := fieldAt(data, "DMAP", 5)
		if err != nil {
			t.Fatal(err)
		}
		values := field.Value.(MapValue)
		found := false
		for i, pair := range values.Pairs {
			if pair.Key == int64(0x70005) {
				if pair.Value != int64(0) {
					t.Fatal("missing status must default inactive")
				}
				found = true
				// Removing just our new key must reproduce the original frame exactly.
				values.Pairs = append(values.Pairs[:i], values.Pairs[i+1:]...)
				break
			}
		}
		if !found {
			t.Fatal("startup readiness value missing")
		}
		field.Value = values
		restored, err := packet.Encode()
		if err != nil || !bytes.Equal(restored, raw) {
			t.Fatal("unrelated session data changed", err)
		}
		again, err := nfs13SessionDataReply(got)
		if err != nil || !bytes.Equal(again, got) {
			t.Fatal("rewrite not idempotent", err)
		}
		values.Pairs = append(values.Pairs, Pair{Key: int64(0x70005), Value: int64(1)})
		field.Value = values
		explicit, _ := packet.Encode()
		preserved, err := nfs13SessionDataReply(explicit)
		if err != nil || !bytes.Equal(preserved, explicit) {
			t.Fatal("explicit status overwritten", err)
		}
		raw[2], raw[3] = 0, 7
		other, err := nfs13SessionDataReply(raw)
		if err != nil || !bytes.Equal(other, raw) {
			t.Fatal("unrelated component changed", err)
		}
	}
}
