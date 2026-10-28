package main

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"testing"
)

func gameRequest(id uint32, start bool) []byte {
	p := []byte{12, 5, 0, 0, 0, 0, 0, 0, 0, 0}
	if start {
		p[5] = 1
	}
	binary.BigEndian.PutUint32(p[6:], id)
	return p
}

func TestGamePresenceLifecycle(t *testing.T) {
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
	if err = writePacket(a.conn, a.out, gameRequest(102, true)); err != nil {
		t.Fatal(err)
	}
	wantStart := []byte{16, 12, 0, 0, 0, 0x2e, 0x1f, 0x3c, 0x2d, 0, 0, 0, 0, 0, 0, 0, 102}
	binary.BigEndian.PutUint32(wantStart[9:13], aid)
	rawWant(t, c, wantStart)
	// New subscriber's roster must already contain the game and start time.
	late, _ := loginPresenceClient(t, b, "Carol")
	if err = writePacket(late.conn, late.out, presenceSync); err != nil {
		t.Fatal(err)
	}
	p, err := readPacket(late.conn, late.in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeFriendRoster(p); err != nil {
		t.Fatal(err)
	}
	status := appendU32(nil, aid)
	status = append(status, 1)
	status = appendU32(status, 102)
	index := bytes.Index(p, status)
	if index < 0 || binary.BigEndian.Uint32(p[index+9:index+13]) == 0 {
		t.Fatalf("missing current game/timestamp: %x", p)
	}
	// Consume Carol's discovery at Bob before checking the stop event.
	rawWant(t, c, friendAddPacket(friendAccount{lateAccountID(b, "Carol"), "Carol"}))
	rawWant(t, c, friendAcceptPacket(lateAccountID(b, "Carol")))
	rawWant(t, c, friendStatusPacket(lateAccountID(b, "Carol"), true))
	if err = writePacket(a.conn, a.out, gameRequest(102, false)); err != nil {
		t.Fatal(err)
	}
	wantStop := []byte{16, 8, 0, 0, 0, 0x2b, 0x4b, 0x43, 0x5f, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(wantStop[9:], aid)
	rawWant(t, c, wantStop)
	rawWant(t, late, wantStop)
}

func lateAccountID(b *backend, name string) uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, a := range b.friends {
		if a.Name == name {
			return id
		}
	}
	return 0
}

func TestDuplicateGameSessionsRetainLiveGame(t *testing.T) {
	b := newBackend(nil, "")
	a := b.startSession(account{ID: 1})
	c := b.startSession(account{ID: 1})
	b.gameEvent(a, 102, true)
	b.gameEvent(c, 102, true)
	// No writers are needed for this ownership test; readiness controls the
	// aggregate used by roster serialization and live notifications.
	a.presenceReady = true
	c.presenceReady = true
	if got := b.activeGamesLocked()[1].ID; got != 102 {
		t.Fatal(got)
	}
	a.offline = true
	if !b.onlineFriendsLocked()[1] || b.activeGamesLocked()[1].ID != 102 {
		t.Fatal("one offline session hid another live session")
	}
	c.offline = true
	if b.onlineFriendsLocked()[1] || len(b.activeGamesLocked()) != 0 {
		t.Fatal("offline account still visible")
	}
	c.offline = false
	b.endSession(a)
	if got := b.activeGamesLocked()[1].ID; got != 102 {
		t.Fatal("old disconnect cleared current game")
	}
	b.endSession(c)
	if len(b.activeGamesLocked()) != 0 {
		t.Fatal("game leaked after last disconnect")
	}
}
