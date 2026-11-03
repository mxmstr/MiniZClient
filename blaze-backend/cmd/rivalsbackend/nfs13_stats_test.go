package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

func statsRequest(t *testing.T, command uint16, name string, vid int64) []byte {
	t.Helper()
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[2:4], 7)
	binary.BigEndian.PutUint16(h[4:6], command)
	fields := []Field{{Tag: "NAME", Kind: 1, Value: []byte(name)}}
	if command == 16 {
		fields = append(fields, Field{Tag: "VID", Kind: 0, Value: vid})
	}
	raw, err := (Packet{Header: h, Fields: fields}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	setBlazeCorrelation(raw, uint32(vid+100))
	return raw
}

func TestNFS13StatsLiveConnectionWithoutReplay(t *testing.T) {
	server := &blazeServer{nfs13: true, advertiseHost: "127.0.0.1"} // Deliberately no corpus.
	client, peer := net.Pipe()
	defer client.Close()
	go server.handle(peer)
	client.SetDeadline(time.Now().Add(5 * time.Second))
	groups := []string{"license_plate", "online_challenge", "license_plate_unlock", "online_concours_challenge"}
	for i := 0; i < 24; i++ {
		group := groups[i%len(groups)]
		for _, cmd := range []uint16{4, 16} {
			request := statsRequest(t, cmd, group, int64(i+1))
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
			raw, err := readBlazeFrame(client)
			if err != nil {
				t.Fatal(err)
			}
			_, _, kind, corr := blazeMetadata(raw)
			if kind != 1 || corr != uint32(i+101) {
				t.Fatalf("bad response metadata %d %d", kind, corr)
			}
			if cmd == 4 {
				if bytes.Contains(raw, []byte("PlayerStats")) || bytes.Contains(raw, []byte("SaveTimestamp")) {
					t.Fatal("foreign stats leaked")
				}
				p, _ := decodePacket(raw)
				scopes, e := mapField(p.Fields, "KSUM")
				if e != nil {
					t.Fatal(e)
				}
				if group == "license_plate" {
					if len(scopes.Pairs) != 0 {
						t.Fatal("selected plate must be unscoped")
					}
				} else if len(scopes.Pairs) != 1 || string(scopes.Pairs[0].Key.([]byte)) != nfs13StatsScopes[group] {
					t.Fatal("wrong descriptor scope")
				}
			} else {
				raw, err = readBlazeFrame(client)
				if err != nil {
					t.Fatal(err)
				}
				comp, command, kind, corr := blazeMetadata(raw)
				if comp != 7 || command != 50 || kind != 2 || corr != 0 {
					t.Fatal("bad notification envelope")
				}
				p, _ := decodePacket(raw)
				vid, _ := integerField(p.Fields, "VID")
				last, _ := integerField(p.Fields, "LAST")
				key, _ := bytesField(p.Fields, "KEY")
				name, _ := bytesField(p.Fields, "GRNM")
				wantKey := nfs13StatsScopes[group] + "=0"
				if group == "license_plate" {
					wantKey = "No_Scope_Defined"
				}
				if vid != int64(i+1) || last != 1 || string(name) != group || string(key) != wantKey {
					t.Fatalf("bad notification: %+v", p.Fields)
				}
			}
		}
	}
	// Unsupported group is an RPC error; it must not close the connection.
	client.Write(statsRequest(t, 4, "unknown", 40))
	raw, err := readBlazeFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if raw[8]>>4 != 3 {
		t.Fatal("missing explicit error")
	}
	client.Write(statsRequest(t, 4, "license_plate", 41))
	if _, err = readBlazeFrame(client); err != nil {
		t.Fatal("connection closed after unknown group", err)
	}
}

func TestNFS13StatsExplicitScope(t *testing.T) {
	raw := statsRequest(t, 16, "online_challenge", 77)
	p, _ := decodePacket(raw)
	p.Fields = append(p.Fields, Field{Tag: "KSUM", Kind: 5, Value: MapValue{KeyKind: 1, ValueKind: 0, Pairs: []Pair{{Key: []byte("online_challenge"), Value: int64(123)}}}})
	raw, _ = p.Encode()
	replies, err := nfs13StatsReplies(raw)
	if err != nil {
		t.Fatal(err)
	}
	notice, _ := decodePacket(replies[1])
	key, _ := bytesField(notice.Fields, "KEY")
	if string(key) != "online_challenge=123" {
		t.Fatalf("key=%q", key)
	}
}

// Request immediately preceding the 0x006E354D crash in capture 62104.
// The native completion callback looks up No_Scope_Defined for the selected
// plate, independently of the scoped map used by unlock/challenge consumers.
func TestNFS13SelectedPlateCrashRegression(t *testing.T) {
	raw, err := hex.DecodeString("003e0007001000000000001e8679f20000969900040001a401ba1b65010e6c6963656e73655f706c61746500c23d320001c2f9a60000c32a640000c34e700000d29b650000da99000001")
	if err != nil {
		t.Fatal(err)
	}
	for _, explicitEmptyScope := range []bool{false, true} {
		request, err := decodePacket(raw)
		if err != nil {
			t.Fatal(err)
		}
		if explicitEmptyScope {
			request.Fields = append(request.Fields, Field{Tag: "KSUM", Kind: 5, Value: MapValue{KeyKind: 1, ValueKind: 0}})
		}
		encoded, err := request.Encode()
		if err != nil {
			t.Fatal(err)
		}
		replies, err := nfs13StatsReplies(encoded)
		if err != nil || len(replies) != 2 {
			t.Fatalf("replies=%d err=%v", len(replies), err)
		}
		notice, err := decodePacket(replies[1])
		if err != nil {
			t.Fatal(err)
		}
		key, err := bytesField(notice.Fields, "KEY")
		if err != nil || string(key) != "No_Scope_Defined" {
			t.Fatalf("native lookup would miss key %q: %v", key, err)
		}
		status, err := structField(notice.Fields, "STS")
		if err != nil {
			t.Fatal(err)
		}
		rows, err := fieldAt(status, "STAT", 4)
		if err != nil {
			t.Fatal(err)
		}
		list := rows.Value.(List)
		if list.Kind != 3 || len(list.Items) != 0 {
			t.Fatal("expected empty result object, not invented progression")
		}
	}
}
