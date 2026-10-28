package main

import (
	"encoding/binary"
	"testing"
)

func TestEmptyBlazeSuccessPreservesRouting(t *testing.T) {
	request := make([]byte, 12)
	binary.BigEndian.PutUint16(request[2:4], 4)
	binary.BigEndian.PutUint16(request[4:6], 13)
	request[9] = 0x0a
	request[10] = 0xbc
	request[11] = 0xde

	reply := emptyBlazeSuccess(request)
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 4 || command != 13 || messageType != 1 ||
		correlation != 0xabcde {
		t.Fatalf("unexpected probe reply metadata: component=%d command=%d type=%d correlation=%#x",
			component, command, messageType, correlation)
	}
	if len(reply) != 12 || binary.BigEndian.Uint16(reply[:2]) != 0 {
		t.Fatalf("probe reply is not an empty Blaze frame: %x", reply)
	}
}
