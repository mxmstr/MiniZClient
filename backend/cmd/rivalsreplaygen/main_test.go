package main

import (
	"encoding/hex"
	"testing"
)

func TestFramesAcceptZClientPrivateComponent(t *testing.T) {
	raw, err := hex.DecodeString("000a780200050000200000009ac9f30003a640000002")
	if err != nil {
		t.Fatal(err)
	}
	decoded, ok := frames(raw)
	if !ok || len(decoded) != 1 {
		t.Fatalf("frames returned %d frame(s), ok=%t", len(decoded), ok)
	}
	component, command, messageType, _ := meta(decoded[0])
	if component != 0x7802 || command != 5 || messageType != 2 {
		t.Fatalf("metadata = %04x/%d type %d", component, command, messageType)
	}
}

func TestFramesSplitsCoalescedRequests(t *testing.T) {
	first, err := hex.DecodeString("0000000100e6000000000005")
	if err != nil {
		t.Fatal(err)
	}
	second, err := hex.DecodeString("00000001001e000000000006")
	if err != nil {
		t.Fatal(err)
	}
	decoded, ok := frames(append(first, second...))
	if !ok || len(decoded) != 2 {
		t.Fatalf("frames returned %d frame(s), ok=%t", len(decoded), ok)
	}
	for index, wantCommand := range []uint16{230, 30} {
		component, command, messageType, _ := meta(decoded[index])
		if component != 1 || command != wantCommand || messageType != 0 {
			t.Fatalf("frame %d metadata = %04x/%d type %d, want 0001/%d type 0",
				index, component, command, messageType, wantCommand)
		}
	}
}
