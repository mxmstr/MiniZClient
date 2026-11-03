package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testLoginPacket(name string, password byte) []byte {
	p := append([]byte{4, 0, 0, 0, 0, 0}, []byte(name)...)
	p = append(p, 0)
	p = append(p, bytes.Repeat([]byte{password}, 16)...)
	p = append(p, bytes.Repeat([]byte{0x99}, 100)...)
	binary.LittleEndian.PutUint32(p[1:5], uint32(len(p)-5))
	return p
}

func TestLoginIdentityIgnoresMachineData(t *testing.T) {
	for _, name := range []string{"A", "LANPlayer", "second.player@lan"} {
		p := testLoginPacket(name, 42)
		for _, tail := range []byte{0, 255} {
			p[len(p)-1] = tail
			got, digest, err := parseLogin(p)
			if err != nil || got != name || !bytes.Equal(digest, bytes.Repeat([]byte{42}, 16)) {
				t.Fatalf("login decode: %q %v", got, err)
			}
		}
		for n := 0; n < 7+len(name)+16; n++ {
			truncated := append([]byte(nil), p[:n]...)
			if n >= 5 {
				binary.LittleEndian.PutUint32(truncated[1:5], uint32(n-5))
			}
			if _, _, err := parseLogin(truncated); err == nil {
				t.Fatalf("accepted truncated login length=%d", n)
			}
		}
	}
}

func TestAccountsPersistAndVerifyCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := openAccountStore(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{7}, 16)
	a, err := s.login("Alice", digest, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.login("Bob", digest, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == 0 || b.ID == 0 || a.ID == b.ID {
		t.Fatal("accounts share an ID")
	}
	s, err = openAccountStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.login("ALICE", digest, "")
	if err != nil || got.ID != a.ID || got.Name != "Alice" {
		t.Fatalf("unstable account: %+v %v", got, err)
	}
	if _, err = s.login("Alice", bytes.Repeat([]byte{8}, 16), ""); err == nil {
		t.Fatal("accepted wrong password")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, digest) {
		t.Fatal("stored raw credential digest")
	}
	if err = os.WriteFile(path, []byte(`{"version":1,"accounts":[{"id":0}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = openAccountStore(path); err == nil {
		t.Fatal("accepted corrupt store")
	}
}

func TestFailedPersistenceDoesNotRegisterAccount(t *testing.T) {
	s, err := openAccountStore(filepath.Join(t.TempDir(), "missing", "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.login("Alice", make([]byte, 16), ""); err == nil {
		t.Fatal("expected persistence error")
	}
	if len(s.accounts) != 0 || s.nextID != 1 {
		t.Fatal("failed save consumed identity")
	}
}

func TestConcurrentRegistrationOfSameUsername(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := openAccountStore(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ids := make([]uint32, 4)
	errs := make([]error, 4)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, err := s.login("Alice", make([]byte, 16), "")
			ids[i], errs[i] = a.ID, err
		}(i)
	}
	wg.Wait()
	for i := range ids {
		if errs[i] != nil || ids[i] != 1 {
			t.Fatalf("duplicate registration: %v %v", ids, errs)
		}
	}
	reloaded, err := openAccountStore(path)
	if err != nil || len(reloaded.accounts) != 1 {
		t.Fatalf("persisted duplicate accounts: %v", err)
	}
}

type testClient struct {
	conn    net.Conn
	in, out *direction
	done    chan struct{}
}

func connectTestClient(t *testing.T, b *backend) *testClient {
	t.Helper()
	server, client := net.Pipe()
	c := &testClient{conn: client, done: make(chan struct{})}
	go func() { defer close(c.done); b.serve(server) }()
	t.Cleanup(func() { client.Close(); <-c.done })
	client.SetDeadline(time.Now().Add(15 * time.Second))
	var err error
	c.out, err = writeServerHello(client, 0xc588f5f6)
	if err != nil {
		t.Fatal(err)
	}
	c.in, _, err = readClientHello(client)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *testClient) exchange(p []byte) ([]byte, error) {
	if err := writePacket(c.conn, c.out, p); err != nil {
		return nil, err
	}
	return readTestPacket(c.conn, c.in)
}

func TestConcurrentUsersAndSessionCleanup(t *testing.T) {
	s, err := openAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := newBackend(s, "")
	a := connectTestClient(t, b)
	c := connectTestClient(t, b)
	clients := []*testClient{a, c}
	names := []string{"Alice", "Bob"}
	ids := make([]uint32, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, e := clients[i].exchange(testLoginPacket(names[i], 1))
			errs[i] = e
			if e == nil {
				ids[i] = binary.BigEndian.Uint32(p[10:14])
			}
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if ids[0] == 0 || ids[1] == 0 || ids[0] == ids[1] {
		t.Fatalf("IDs: %v", ids)
	}
	request := append([]byte{16, 0, 0, 0, 0, 0x83, 0x49, 0x65, 0xa4}, []byte("\x00presence\x00driving\x00")...)
	binary.LittleEndian.PutUint32(request[1:5], uint32(len(request)-5))
	for i, c := range clients {
		p, e := c.exchange(request)
		if e != nil {
			t.Fatal(e)
		}
		if got := binary.BigEndian.Uint32(p[9:13]); got != ids[i] {
			t.Fatalf("cross-user reply ID=%d want=%d", got, ids[i])
		}
	}
	// A second connection for Alice has the same account and its own session.
	reconnect := connectTestClient(t, b)
	p, err := reconnect.exchange(testLoginPacket("Alice", 1))
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(p[10:14]) != ids[0] {
		t.Fatal("reconnect changed identity")
	}
	a.conn.Close()
	<-a.done
	b.mu.Lock()
	count := len(b.sessions)
	b.mu.Unlock()
	if count != 2 {
		t.Fatalf("disconnect removed other sessions: %d", count)
	}
	for _, client := range []*testClient{c, reconnect} {
		p, err = client.exchange([]byte{0, 0, 0, 0, 0})
		if err != nil || !bytes.Equal(p, []byte{0, 0, 0, 0, 0}) {
			t.Fatalf("surviving session failed: %v", err)
		}
		client.conn.Close()
		<-client.done
	}
	b.mu.Lock()
	count = len(b.sessions)
	b.mu.Unlock()
	if count != 0 {
		t.Fatal("session registry leaked")
	}
}

func TestUnauthenticatedAndWrongPasswordSessionsClose(t *testing.T) {
	s, err := openAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.login("Alice", bytes.Repeat([]byte{1}, 16), ""); err != nil {
		t.Fatal(err)
	}
	b := newBackend(s, "")
	for _, p := range [][]byte{{16, 4, 0, 0, 0, 0x68, 0xaf, 0xa2, 9}, testLoginPacket("Alice", 2)} {
		c := connectTestClient(t, b)
		if _, err = c.exchange(p); err == nil {
			t.Fatal("unauthenticated request accepted")
		}
		<-c.done
	}
	if len(b.sessions) != 0 {
		t.Fatal("rejected login created a session")
	}
}
