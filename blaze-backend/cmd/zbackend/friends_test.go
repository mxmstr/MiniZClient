package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"path/filepath"
	"testing"
)

// Presence-only regression tests ignore the newly supported roster deltas.
// Discovery tests below read the raw stream to verify their exact ordering.
func readTestPacket(r io.Reader, d *direction) ([]byte, error) {
	for {
		p, err := readPacket(r, d)
		if err != nil {
			return nil, err
		}
		if len(p) >= 9 && p[0] == 16 {
			c := binary.BigEndian.Uint32(p[5:9])
			if c == friendAddCommand || c == friendAcceptCommand || c == friendStatusCommand {
				continue
			}
		}
		return p, nil
	}
}

type decodedFriend struct {
	name   string
	online bool
}

// Independent reader mirrors the verified five-list client schema and
// rejects extra bytes, misplaced terminators and status-only identities.
func decodeFriendRoster(p []byte) (map[uint32]decodedFriend, error) {
	bad := errors.New("invalid friend roster")
	if len(p) < 29 || p[0] != 16 || binary.LittleEndian.Uint32(p[1:5]) != uint32(len(p)-5) || !bytes.Equal(p[5:9], []byte{0x68, 0xaf, 0xa2, 9}) {
		return nil, bad
	}
	r := bytes.NewBuffer(p[9:])
	result := make(map[uint32]decodedFriend)
	u32 := func() (uint32, error) { var v uint32; e := binary.Read(r, binary.BigEndian, &v); return v, e }
	for group := 0; group < 4; group++ {
		for {
			id, e := u32()
			if e != nil {
				return nil, e
			}
			if id == 0 {
				break
			}
			if group != 2 {
				return nil, bad
			}
			if _, exists := result[id]; exists {
				return nil, bad
			}
			name, e := r.ReadString(0)
			if e != nil {
				return nil, e
			}
			avatar, e := u32()
			if e != nil || avatar != 0 {
				return nil, bad
			}
			result[id] = decodedFriend{name: name[:len(name)-1]}
		}
	}
	seen := make(map[uint32]bool)
	for {
		id, e := u32()
		if e != nil {
			return nil, e
		}
		if id == 0 {
			break
		}
		f, exists := result[id]
		if !exists || seen[id] {
			return nil, bad
		}
		seen[id] = true
		status, e := r.ReadByte()
		if e != nil || status > 1 {
			return nil, bad
		}
		f.online = status == 1
		if f.online {
			metadata := make([]byte, 12)
			if _, e = io.ReadFull(r, metadata); e != nil {
				return nil, bad
			}
			for scope := 0; scope < 2; scope++ {
				var count uint16
				if scope == 0 {
					e = binary.Read(r, binary.BigEndian, &count)
				} else {
					var n byte
					n, e = r.ReadByte()
					count = uint16(n)
				}
				if e != nil {
					return nil, bad
				}
				for i := uint16(0); i < count; i++ {
					if _, e = r.ReadString(0); e != nil {
						return nil, bad
					}
					if _, e = r.ReadString(0); e != nil {
						return nil, bad
					}
				}
			}
		}
		result[id] = f
	}
	if r.Len() != 0 || len(seen) != len(result) {
		return nil, bad
	}
	return result, nil
}

func rawRoster(t *testing.T, c *testClient) map[uint32]decodedFriend {
	t.Helper()
	if err := writePacket(c.conn, c.out, presenceSync); err != nil {
		t.Fatal(err)
	}
	p, err := readPacket(c.conn, c.in)
	if err != nil {
		t.Fatal(err)
	}
	result, err := decodeFriendRoster(p)
	if err != nil {
		t.Fatalf("roster %x: %v", p, err)
	}
	return result
}

func rawWant(t *testing.T, c *testClient, want []byte) {
	t.Helper()
	p, err := readPacket(c.conn, c.in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, want) {
		t.Fatalf("got %x want %x", p, want)
	}
}

func TestFriendPacketLayouts(t *testing.T) {
	b := newBackend(nil, "")
	s := b.startSession(account{ID: 1, Name: "Alice"})
	b.startSession(account{ID: 2, Name: "Bob"})
	p, _, err := b.friendRosterLocked(s)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{16, 41, 0, 0, 0, 0x68, 0xaf, 0xa2, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 'B', 'o', 'b', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0}
	// Payload: command 4 + relation terminators 16 + Bob 12 + status 5 + status terminator 4.
	if !bytes.Equal(p, want) {
		t.Fatalf("roster got=%x want=%x", p, want)
	}
	if got := friendAddPacket(friendAccount{2, "Bob"}); !bytes.Equal(got, []byte{16, 16, 0, 0, 0, 0xb3, 0x5c, 0x31, 0x85, 0, 0, 0, 2, 'B', 'o', 'b', 0, 0, 0, 0, 0}) {
		t.Fatalf("add %x", got)
	}
	if got := friendStatusPacket(2, true); !bytes.Equal(got, []byte{16, 9, 0, 0, 0, 0, 0x5e, 0xf2, 0x0f, 0, 0, 0, 2, 1}) {
		t.Fatalf("status %x", got)
	}
}

func TestLiveFriendDiscoveryAndLastSessionOffline(t *testing.T) {
	store, err := openAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := newBackend(store, "")
	a, aid := loginPresenceClient(t, b, "Alice")
	if got := rawRoster(t, a); len(got) != 0 {
		t.Fatalf("self discovery: %v", got)
	}
	key := presenceKey{0, "Z_GAME_PRESENCE"}
	if _, err = a.exchange(presenceRequest(key, "Driving", false)); err != nil {
		t.Fatal(err)
	}
	c, cid := loginPresenceClient(t, b, "Bob")
	roster := rawRoster(t, c)
	if len(roster) != 1 || roster[aid] != (decodedFriend{"Alice", true}) {
		t.Fatalf("late join roster: %v", roster)
	}
	rawWant(t, c, presencePacket(aid, key, "Driving", false))
	rawWant(t, a, friendAddPacket(friendAccount{cid, "Bob"}))
	rawWant(t, a, friendAcceptPacket(cid))
	rawWant(t, a, friendStatusPacket(cid, true))
	second, _ := loginPresenceClient(t, b, "Bob")
	rawRoster(t, second)
	rawWant(t, second, presencePacket(aid, key, "Driving", false))
	c.conn.Close()
	<-c.done
	if err = writePacket(a.conn, a.out, []byte{0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rawWant(t, a, []byte{0, 0, 0, 0, 0}) // no duplicate add or false offline
	second.conn.Close()
	<-second.done
	rawWant(t, a, friendStatusPacket(cid, false))
	roster = rawRoster(t, a)
	if len(roster) != 1 || roster[cid] != (decodedFriend{"Bob", false}) {
		t.Fatalf("offline friend lost: %v", roster)
	}
	rawWant(t, a, presencePacket(aid, key, "Driving", false))
	returned, _ := loginPresenceClient(t, b, "Bob")
	rawRoster(t, returned)
	rawWant(t, returned, presencePacket(aid, key, "Driving", false))
	rawWant(t, a, friendStatusPacket(cid, true)) // already-known friend, no add
}

func TestFriendDiscoveryFromPersistedAccounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := openAccountStore(path)
	if err != nil {
		t.Fatal(err)
	}
	offline, err := store.login("Offline", make([]byte, 16), "José")
	if err != nil {
		t.Fatal(err)
	}
	store, err = openAccountStore(path)
	if err != nil {
		t.Fatal(err)
	}
	b := newBackend(store, "")
	c, _ := loginPresenceClient(t, b, "Alice")
	roster := rawRoster(t, c)
	if len(roster) != 1 || roster[offline.ID] != (decodedFriend{"José", false}) {
		t.Fatalf("persisted roster: %v", roster)
	}
}

func TestFriendDiscoveryAuthCompleteFallback(t *testing.T) {
	store, err := openAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := newBackend(store, "")
	a, aid := loginPresenceClient(t, b, "Alice")
	rawRoster(t, a)
	c, cid := loginPresenceClient(t, b, "Bob")
	// Login alone must not subscribe Bob to unsolicited roster changes.
	if err = writePacket(c.conn, c.out, []byte{0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rawWant(t, c, []byte{0, 0, 0, 0, 0})
	request := []byte{17, 5, 0, 0, 0, 2, 0x8d, 0x29, 0x37, 0xa1}
	if err = writePacket(c.conn, c.out, request); err != nil {
		t.Fatal(err)
	}
	rawWant(t, c, authCompleteNotification())
	p, err := readPacket(c.conn, c.in)
	if err != nil {
		t.Fatal(err)
	}
	roster, err := decodeFriendRoster(p)
	if err != nil || len(roster) != 1 || roster[aid] != (decodedFriend{"Alice", true}) {
		t.Fatalf("fallback roster %v %v", roster, err)
	}
	rawWant(t, a, friendAddPacket(friendAccount{cid, "Bob"}))
	rawWant(t, a, friendAcceptPacket(cid))
	rawWant(t, a, friendStatusPacket(cid, true))
	// A repeated auth-complete request must not repeat roster notifications.
	if err = writePacket(c.conn, c.out, request); err != nil {
		t.Fatal(err)
	}
	rawWant(t, c, authCompleteNotification())
	if err = writePacket(c.conn, c.out, []byte{0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rawWant(t, c, []byte{0, 0, 0, 0, 0})
}
