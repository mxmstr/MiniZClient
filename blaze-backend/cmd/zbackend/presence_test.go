package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var presenceSync = []byte{16, 4, 0, 0, 0, 0x68, 0xaf, 0xa2, 9}

func presenceRequest(key presenceKey, value string, remove bool) []byte {
	p := presencePacket(1, key, value, remove)
	p = append(p[:9], p[13:]...)
	binary.LittleEndian.PutUint32(p[1:5], uint32(len(p)-5))
	return p
}

func loginPresenceClient(t *testing.T, b *backend, name string) (*testClient, uint32) {
	t.Helper()
	c := connectTestClient(t, b)
	p, err := c.exchange(testLoginPacket(name, 1))
	if err != nil {
		t.Fatal(err)
	}
	return c, binary.BigEndian.Uint32(p[10:14])
}

func readPresencePacket(t *testing.T, c *testClient, want []byte) {
	t.Helper()
	p, err := readTestPacket(c.conn, c.in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, want) {
		t.Fatalf("packet got=%x want=%x", p, want)
	}
}

func syncPresenceClient(t *testing.T, c *testClient) {
	t.Helper()
	p, err := c.exchange(presenceSync)
	if err != nil {
		t.Fatalf("sync response: %x %v", p, err)
	}
	if _, err := decodeFriendRoster(p); err != nil {
		t.Fatal(err)
	}
}

func TestSharedPresenceEncryptedClients(t *testing.T) {
	s, err := openAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := newBackend(s, "")
	a, aid := loginPresenceClient(t, b, "Alice")
	syncPresenceClient(t, a)
	key := presenceKey{0, "Z_GAME_PRESENCE"}
	request := presenceRequest(key, "Driving", false)
	want := presencePacket(aid, key, "Driving", false)
	p, err := a.exchange(request)
	if err != nil || !bytes.Equal(p, want) {
		t.Fatalf("origin echo %x %v", p, err)
	}
	// Late join receives sync first, then an account-keyed snapshot.
	c, _ := loginPresenceClient(t, b, "Bob")
	syncPresenceClient(t, c)
	readPresencePacket(t, c, want)
	// Repeated sync must replay state after the client's clearing sync reply.
	syncPresenceClient(t, c)
	readPresencePacket(t, c, want)
	request = presenceRequest(key, "Racing", false)
	want = presencePacket(aid, key, "Racing", false)
	p, err = a.exchange(request)
	if err != nil || !bytes.Equal(p, want) {
		t.Fatalf("update echo %x %v", p, err)
	}
	readPresencePacket(t, c, want)
	request = presenceRequest(key, "", true)
	want = presencePacket(aid, key, "", true)
	p, err = a.exchange(request)
	if err != nil || !bytes.Equal(p, want) {
		t.Fatalf("removal echo %x %v", p, err)
	}
	readPresencePacket(t, c, want)
	// A third client must not receive the removed value; heartbeat acts as a
	// deterministic end marker after its empty snapshot.
	d, _ := loginPresenceClient(t, b, "Carol")
	syncPresenceClient(t, d)
	p, err = d.exchange([]byte{0, 0, 0, 0, 0})
	if err != nil || p[0] != 0 {
		t.Fatalf("stale snapshot: %x %v", p, err)
	}
	request = presenceRequest(key, "Driving", false)
	if _, err = a.exchange(request); err != nil {
		t.Fatal(err)
	}
	readPresencePacket(t, c, presencePacket(aid, key, "Driving", false))
	readPresencePacket(t, d, presencePacket(aid, key, "Driving", false))
	a.conn.Close()
	<-a.done
	readPresencePacket(t, c, presencePacket(aid, key, "", true))
	readPresencePacket(t, d, presencePacket(aid, key, "", true))
}

func TestSameAccountDisconnectPreservesNewerPresence(t *testing.T) {
	s, err := openAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := newBackend(s, "")
	a, id := loginPresenceClient(t, b, "Alice")
	c, _ := loginPresenceClient(t, b, "Alice")
	observer, _ := loginPresenceClient(t, b, "Bob")
	syncPresenceClient(t, observer)
	key := presenceKey{1, "EA_GAME_PRESENCE"}
	for i, client := range []*testClient{a, c} {
		value := fmt.Sprint(i)
		if _, err = client.exchange(presenceRequest(key, value, false)); err != nil {
			t.Fatal(err)
		}
		readPresencePacket(t, observer, presencePacket(id, key, value, false))
	}
	a.conn.Close()
	<-a.done
	p, err := observer.exchange([]byte{0, 0, 0, 0, 0})
	if err != nil || p[0] != 0 {
		t.Fatalf("older session cleared newer presence: %x %v", p, err)
	}
	c.conn.Close()
	<-c.done
	readPresencePacket(t, observer, presencePacket(id, key, "", true))
}

func TestConcurrentPresenceAndRepliesStayFramed(t *testing.T) {
	s, err := openAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := newBackend(s, "")
	a, aid := loginPresenceClient(t, b, "Alice")
	c, cid := loginPresenceClient(t, b, "Bob")
	syncPresenceClient(t, a)
	syncPresenceClient(t, c)
	const count = 12
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for _, client := range []*testClient{a, c} {
		wg.Add(2)
		go func(c *testClient) {
			defer wg.Done()
			for i := 0; i < count; i++ {
				if e := writePacket(c.conn, c.out, presenceRequest(presenceKey{0, "presence"}, fmt.Sprint(i), false)); e != nil {
					errs <- e
					return
				}
				if e := writePacket(c.conn, c.out, []byte{0, 0, 0, 0, 0}); e != nil {
					errs <- e
					return
				}
			}
		}(client)
		go func(c *testClient) {
			defer wg.Done()
			seen := map[uint32]int{aid: 0, cid: 0}
			beats := 0
			for i := 0; i < 3*count; i++ {
				p, e := readTestPacket(c.conn, c.in)
				if e != nil {
					errs <- e
					return
				}
				if bytes.Equal(p, []byte{0, 0, 0, 0, 0}) {
					beats++
					continue
				}
				if len(p) < 13 {
					errs <- fmt.Errorf("invalid presence packet %x", p)
					return
				}
				id := binary.BigEndian.Uint32(p[9:13])
				n, ok := seen[id]
				if !ok || !bytes.Equal(p, presencePacket(id, presenceKey{0, "presence"}, fmt.Sprint(n), false)) {
					errs <- fmt.Errorf("out-of-order packet %x", p)
					return
				}
				seen[id]++
			}
			if beats != count || seen[aid] != count || seen[cid] != count {
				errs <- fmt.Errorf("missing replies: %d %v", beats, seen)
			}
		}(client)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSlowPresenceSubscriberIsDisconnected(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	d, err := directionFromClear([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	w := newPacketWriter(server, d)
	defer w.close()
	// The peer never reads: one packet can be in flight and the rest fill
	// the bounded queue. No producer should wait on the blocked socket.
	done := make(chan error, 1)
	go func() {
		for i := 0; i < maxQueuedPackets+2; i++ {
			if e := w.send([]byte{0, 0, 0, 0, 0}); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("slow subscriber was not disconnected")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queue blocked its producer")
	}
}

func TestMalformedPresenceDoesNotPartiallyPublish(t *testing.T) {
	store, err := openAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := newBackend(store, "")
	a, _ := loginPresenceClient(t, b, "Alice")
	observer, _ := loginPresenceClient(t, b, "Bob")
	syncPresenceClient(t, observer)
	malformed := presenceRequest(presenceKey{0, "key"}, "valid", false)
	malformed = append(malformed, 0, 'x') // truncated second record
	binary.LittleEndian.PutUint32(malformed[1:5], uint32(len(malformed)-5))
	if err = writePacket(a.conn, a.out, malformed); err != nil {
		t.Fatal(err)
	}
	p, err := a.exchange([]byte{0, 0, 0, 0, 0})
	if err != nil || p[0] != 0 {
		t.Fatalf("malformed request reply: %x %v", p, err)
	}
	p, err = observer.exchange([]byte{0, 0, 0, 0, 0})
	if err != nil || p[0] != 0 {
		t.Fatalf("partial broadcast: %x %v", p, err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.presence) != 0 {
		t.Fatal("malformed request mutated shared state")
	}
}

func TestPresenceKeyLimitRejectsWholeUpdate(t *testing.T) {
	b := newBackend(nil, "")
	s := b.startSession(account{ID: 1})
	values := make(map[presenceKey]sharedPresence)
	for i := 0; i < maxPresenceKeys; i++ {
		values[presenceKey{0, fmt.Sprint(i)}] = sharedPresence{"old", s.id}
	}
	b.presence[1] = values
	p := presenceRequest(presenceKey{0, "0"}, "changed", false)
	extra := presenceRequest(presenceKey{0, "new"}, "new", false)
	p = append(p, extra[9:]...)
	binary.LittleEndian.PutUint32(p[1:5], uint32(len(p)-5))
	if err := b.handleDatastore(s, p); err == nil {
		t.Fatal("accepted oversized state")
	}
	if len(values) != maxPresenceKeys || values[presenceKey{0, "0"}].value != "old" {
		t.Fatal("partially applied rejected update")
	}
}
