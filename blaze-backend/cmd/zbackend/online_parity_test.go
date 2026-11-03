package main

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"testing"
)

func TestOnlineCapturedRoster(t *testing.T) {
	// Packet 26 from the September 10 capture, with peer ID/name anonymized.
	// The two empty groups BEFORE RemotePlayer distinguish accepted from pending.
	want, err := hex.DecodeString("106900000068afa20900000000000000000000000252656d6f7465506c617965720000000000000000000000000000000002010000000000000000000000000000014f524947494e5f5645520031757a4565676550645472476d4456374f5574363643377062774d3d0000000000")
	if err != nil {
		t.Fatal(err)
	}
	b := newBackend(nil, "")
	self := b.startSession(account{ID: 1, Name: "Self"})
	peer := b.startSession(account{ID: 2, Name: "RemotePlayer"})
	peer.presenceReady = true
	b.presence[2] = map[presenceKey]sharedPresence{{1, "ORIGIN_VER"}: {"1uzEegePdTrGmDV7OUt66C7pbwM=", peer.id}}
	got, _, err := b.friendRosterLocked(self)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("roster got=%x want=%x error=%v", got, want, err)
	}
	if _, err = decodeFriendRoster(want); err != nil {
		t.Fatal(err)
	}
}

func TestClientStatusTransitions(t *testing.T) {
	store, err := openAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := newBackend(store, "")
	a, aid := loginPresenceClient(t, b, "Alice")
	rawRoster(t, a)
	c, cid := loginPresenceClient(t, b, "Bob")
	rawRoster(t, c)
	rawWant(t, a, friendAddPacket(friendAccount{cid, "Bob"}))
	rawWant(t, a, friendAcceptPacket(cid))
	rawWant(t, a, friendStatusPacket(cid, true))
	for _, status := range []byte{0, 1} {
		request := []byte{16, 5, 0, 0, 0, 0, 0x5e, 0xf2, 0x0f, status}
		if err = writePacket(a.conn, a.out, request); err != nil {
			t.Fatal(err)
		}
		// The online capture has no direct response; a heartbeat is a barrier.
		if err = writePacket(a.conn, a.out, []byte{0, 0, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
		rawWant(t, a, []byte{0, 0, 0, 0, 0})
		if status == 0 {
			rawWant(t, c, friendStatusPacket(aid, false))
		}
		if status == 1 {
			break
		}
	}
	rawWant(t, c, friendStatusPacket(aid, true))
	request := []byte{16, 5, 0, 0, 0, 0, 0x5e, 0xf2, 0x0f, 1}
	if err = writePacket(a.conn, a.out, request); err != nil {
		t.Fatal(err)
	}
	if _, err = a.exchange([]byte{0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if err = writePacket(c.conn, c.out, []byte{0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rawWant(t, c, []byte{0, 0, 0, 0, 0})
}
