package main

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const passwordIterations = 600000

type account struct {
	ID       uint32 `json:"id"`
	Login    string `json:"login"`
	Name     string `json:"name"`
	Salt     string `json:"salt"`
	Verifier string `json:"verifier"`
}

type accountFile struct {
	Version  int       `json:"version"`
	Accounts []account `json:"accounts"`
}

// One store belongs to one backend process. The mutex covers allocation and
// persistence together, so no login succeeds before its identity is durable.
type accountStore struct {
	mu       sync.Mutex
	path     string
	accounts map[string]account
	nextID   uint32
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > 64 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// September payload 63C198D0 constructs subtype 0, login\0, a 16-byte
// password digest, then machine data. 63E855A0 -> 6402AF50 -> 64035A30
// sends this buffer as type 4 unchanged. Machine data is not an account key.
func parseLogin(packet []byte) (string, []byte, error) {
	if len(packet) < 24 || packet[0] != 4 || packet[5] != 0 || binary.LittleEndian.Uint32(packet[1:5]) != uint32(len(packet)-5) {
		return "", nil, errors.New("unsupported login layout")
	}
	end := bytes.IndexByte(packet[6:], 0)
	if end < 1 || end > 64 || len(packet) < 6+end+1+16 {
		return "", nil, errors.New("malformed login")
	}
	login := string(packet[6 : 6+end])
	if !validName(login) {
		return "", nil, errors.New("invalid login name")
	}
	return login, packet[7+end : 7+end+16], nil
}

func openAccountStore(path string) (*accountStore, error) {
	s := &accountStore{path: path, accounts: make(map[string]account), nextID: 1}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var file accountFile
	if err = json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.Version != 1 {
		return nil, errors.New("unsupported accounts file version")
	}
	ids := make(map[uint32]bool)
	for _, a := range file.Accounts {
		key := strings.ToLower(a.Login)
		salt, e1 := hex.DecodeString(a.Salt)
		verifier, e2 := hex.DecodeString(a.Verifier)
		if a.ID == 0 || ids[a.ID] || s.accounts[key].ID != 0 || !validName(a.Login) || !validName(a.Name) || e1 != nil || e2 != nil || len(salt) != 16 || len(verifier) != 32 {
			return nil, errors.New("invalid or duplicate account record")
		}
		ids[a.ID] = true
		s.accounts[key] = a
		if a.ID >= s.nextID {
			s.nextID = a.ID + 1
		}
	}
	if ids[^uint32(0)] {
		s.nextID = 0
	}
	return s, nil
}

func (s *accountStore) login(login string, digest []byte, displayName string) (account, error) {
	if !validName(login) || len(digest) != 16 || (displayName != "" && !validName(displayName)) {
		return account{}, errors.New("invalid account input")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(login)
	a, exists := s.accounts[key]
	if exists {
		salt, _ := hex.DecodeString(a.Salt)
		want, _ := hex.DecodeString(a.Verifier)
		got, err := pbkdf2.Key(sha256.New, string(digest), salt, passwordIterations, 32)
		if err != nil {
			return account{}, err
		}
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return account{}, errors.New("invalid local credentials")
		}
		return a, nil
	}
	if s.nextID == 0 {
		return account{}, errors.New("account IDs exhausted")
	}
	if displayName == "" {
		displayName = login
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return account{}, err
	}
	verifier, err := pbkdf2.Key(sha256.New, string(digest), salt, passwordIterations, 32)
	if err != nil {
		return account{}, err
	}
	a = account{ID: s.nextID, Login: login, Name: displayName, Salt: hex.EncodeToString(salt), Verifier: hex.EncodeToString(verifier)}
	file := accountFile{Version: 1, Accounts: make([]account, 0, len(s.accounts)+1)}
	for _, existing := range s.accounts {
		file.Accounts = append(file.Accounts, existing)
	}
	file.Accounts = append(file.Accounts, a)
	sort.Slice(file.Accounts, func(i, j int) bool { return file.Accounts[i].ID < file.Accounts[j].ID })
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return account{}, err
	}
	if err = writeAccounts(s.path, append(data, '\n')); err != nil {
		return account{}, fmt.Errorf("save account: %w", err)
	}
	s.accounts[key] = a
	s.nextID++
	return a, nil
}

func writeAccounts(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".accounts-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

type presenceKey struct {
	scope byte
	key   string
}

// Presence, readiness, and registry access are protected by backend.mu.
// Game and auth-completion state belong to the connection loop.
type session struct {
	id            uint64
	account       account
	authComplete  bool
	games         map[uint32]activeGame
	writer        *packetWriter
	presenceReady bool
	offline       bool
	knownFriends  map[uint32]bool
	knownGames    map[uint32]uint32
}

type backend struct {
	accounts         *accountStore
	displayName      string
	mu               sync.Mutex
	nextSession      uint64
	sessions         map[uint64]*session
	presence         map[uint32]map[presenceKey]sharedPresence
	friends          map[uint32]friendAccount
	nextGameSequence uint64
}

func newBackend(accounts *accountStore, displayName string) *backend {
	friends := make(map[uint32]friendAccount)
	if accounts != nil {
		friends = accounts.directory()
	}
	return &backend{accounts: accounts, displayName: displayName, sessions: make(map[uint64]*session), presence: make(map[uint32]map[presenceKey]sharedPresence), friends: friends}
}

func (b *backend) startSession(a account) *session {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextSession++
	s := &session{id: b.nextSession, account: a, games: make(map[uint32]activeGame), knownFriends: make(map[uint32]bool), knownGames: make(map[uint32]uint32)}
	b.friends[a.ID] = friendAccount{a.ID, a.Name}
	b.sessions[s.id] = s
	return s
}

func (b *backend) endSession(s *session) {
	if s == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, s.id)
	b.removeSessionPresenceLocked(s)
	b.refreshFriendsLocked()
}
