package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	maxQueuedPackets        = 256
	maxQueuedBytes          = 1 << 20
	maxPresencePacket       = 16 << 10
	maxPresenceKeys         = 256
	maxAccountPresenceBytes = 64 << 10
)

// All post-handshake writes, including replies, go through this single owner
// of the outbound CBC state. Enqueue never waits on network I/O.
type packetWriter struct {
	conn     net.Conn
	out      *direction
	queue    chan []byte
	done     chan struct{}
	finished chan struct{}
	mu       sync.Mutex
	bytes    int
	stopped  bool
}

func newPacketWriter(conn net.Conn, out *direction) *packetWriter {
	w := &packetWriter{conn: conn, out: out, queue: make(chan []byte, maxQueuedPackets), done: make(chan struct{}), finished: make(chan struct{})}
	go w.run()
	return w
}

func (w *packetWriter) stop() {
	w.mu.Lock()
	if !w.stopped {
		w.stopped = true
		close(w.done)
	}
	w.mu.Unlock()
	w.conn.Close() // also interrupts a blocked read/write
}

func (w *packetWriter) close() { w.stop(); <-w.finished }

func (w *packetWriter) send(packet []byte) error {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return net.ErrClosed
	}
	if len(packet) <= maxQueuedBytes-w.bytes {
		select {
		case w.queue <- append([]byte(nil), packet...):
			w.bytes += len(packet)
			w.mu.Unlock()
			return nil
		default:
		}
	}
	w.mu.Unlock()
	w.stop()
	return errors.New("outbound queue full; disconnected slow client")
}

func (w *packetWriter) run() {
	defer close(w.finished)
	defer w.stop()
	for {
		select {
		case <-w.done:
			return
		case p := <-w.queue:
			w.mu.Lock()
			w.bytes -= len(p)
			stopped := w.stopped
			w.mu.Unlock()
			if stopped {
				return
			}
			if err := w.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return
			}
			if err := writePacket(w.conn, w.out, p); err != nil {
				log.Printf("%s send: %v", w.conn.RemoteAddr(), err)
				return
			}
		}
	}
}

type sharedPresence struct {
	value string
	owner uint64
}

func (b *backend) attachWriter(s *session, w *packetWriter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s.writer = w
}

func presencePacket(id uint32, key presenceKey, value string, remove bool) []byte {
	command := uint32(0x834965a4)
	if remove {
		command = 0x6258ae09
	}
	p := make([]byte, 14)
	p[0] = 16
	binary.BigEndian.PutUint32(p[5:9], command)
	binary.BigEndian.PutUint32(p[9:13], id)
	p[13] = key.scope
	p = append(p, []byte(key.key)...)
	p = append(p, 0)
	if !remove {
		p = append(p, []byte(value)...)
		p = append(p, 0)
	}
	binary.LittleEndian.PutUint32(p[1:5], uint32(len(p)-5))
	return p
}

func sortedPresenceKeys(values map[presenceKey]sharedPresence) []presenceKey {
	keys := make([]presenceKey, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].scope != keys[j].scope {
			return keys[i].scope < keys[j].scope
		}
		return keys[i].key < keys[j].key
	})
	return keys
}

// The caller holds b.mu across synchronization and subsequent subscription.
// A concurrent mutation can therefore neither overtake nor miss the snapshot.
func (b *backend) snapshotLocked(s *session) error {
	ids := make([]uint32, 0, len(b.presence))
	for id := range b.presence {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	visible := make(map[uint32]bool)
	for _, peer := range b.sessions {
		if !peer.offline {
			visible[peer.account.ID] = true
		}
	}
	for _, id := range ids {
		if id != s.account.ID && !visible[id] {
			continue
		}
		var packet []byte
		for _, key := range sortedPresenceKeys(b.presence[id]) {
			record := presencePacket(id, key, b.presence[id][key].value, false)
			if len(packet) > 0 && len(packet)+len(record)-13 > maxPresencePacket {
				if err := s.writer.send(packet); err != nil {
					return err
				}
				packet = nil
			}
			if len(packet) == 0 {
				packet = record
			} else {
				packet = append(packet, record[13:]...)
			}
			binary.LittleEndian.PutUint32(packet[1:5], uint32(len(packet)-5))
		}
		if len(packet) > 0 {
			if err := s.writer.send(packet); err != nil {
				return err
			}
		}
	}
	s.presenceReady = true
	b.refreshFriendsLocked()
	return nil
}

func (b *backend) completePresenceSync(s *session, notification []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := s.writer.send(notification); err != nil {
		return err
	}
	if !s.presenceReady {
		if err := b.sendFriendRosterLocked(s); err != nil {
			return err
		}
		return b.snapshotLocked(s)
	}
	return nil
}

func (b *backend) broadcastPresenceLocked(packet []byte, sender *session) {
	for _, peer := range b.sessions {
		if peer == sender || !peer.presenceReady || peer.writer == nil {
			continue
		}
		if err := peer.writer.send(packet); err != nil {
			log.Printf("presence subscriber session=%d: %v", peer.id, err)
		}
	}
}

func (b *backend) handleDatastore(s *session, request []byte) error {
	if len(request) > maxPresencePacket {
		return errors.New("datastore packet exceeds presence limit")
	}
	// Status requests carry just the status byte; server notifications add ID.
	if len(request) == 10 && request[0] == 16 && binary.LittleEndian.Uint32(request[1:5]) == 5 && binary.BigEndian.Uint32(request[5:9]) == friendStatusCommand {
		if request[9] > 1 {
			return errors.New("invalid online status")
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.sessions[s.id] != s {
			return net.ErrClosed
		}
		s.offline = request[9] == 0
		b.refreshFriendsLocked()
		return nil
	}
	response := datastoreResponse(request, s.account.ID)
	if response == nil {
		log.Printf("unsupported or malformed datastore request; no reply sent")
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sessions[s.id] != s {
		return net.ErrClosed
	}
	command := binary.BigEndian.Uint32(request[5:9])
	if command == 0x68afa209 {
		if err := b.sendFriendRosterLocked(s); err != nil {
			return err
		}
		return b.snapshotLocked(s)
	}
	values := b.presence[s.account.ID]
	if values == nil {
		values = make(map[presenceKey]sharedPresence)
	}
	// Decode into a temporary map before mutating shared state, so the key
	// limit rejects an entire update rather than partially publishing it.
	if command == 0x834965a4 {
		updates := decodePresenceUpdate(request)
		count := len(values)
		size := 0
		for k, v := range values {
			size += len(k.key) + len(v.value) + 3
		}
		for k, v := range updates {
			if _, exists := values[k]; !exists {
				count++
			} else {
				size -= len(k.key) + len(values[k].value) + 3
			}
			size += len(k.key) + len(v) + 3
		}
		if count > maxPresenceKeys || size > maxAccountPresenceBytes {
			return errors.New("account presence limit exceeded")
		}
		scope1 := 0
		for k := range values {
			if k.scope == 1 {
				scope1++
			}
		}
		for k := range updates {
			if _, exists := values[k]; !exists && k.scope == 1 {
				scope1++
			}
		}
		if scope1 > 255 {
			return errors.New("scope-1 presence limit exceeded")
		}
		for k, v := range updates {
			values[k] = sharedPresence{v, s.id}
		}
		b.presence[s.account.ID] = values
	} else if command == 0x6258ae09 {
		delete(values, presenceKey{request[9], string(request[10 : len(request)-1])})
		if len(values) == 0 {
			delete(b.presence, s.account.ID)
		}
	}
	// Echo exactly once, even when the origin has not subscribed yet.
	err := s.writer.send(response)
	b.refreshFriendsLocked()
	if !s.offline || b.onlineFriendsLocked()[s.account.ID] {
		b.broadcastPresenceLocked(response, s)
	}
	log.Printf("shared presence account=%d session=%d command=%08x", s.account.ID, s.id, command)
	return err
}

// Only called after datastoreResponse has validated every record.
func decodePresenceUpdate(request []byte) map[presenceKey]string {
	updates := make(map[presenceKey]string)
	for rest := request[9:]; len(rest) > 0; {
		scope := rest[0]
		rest = rest[1:]
		end := bytes.IndexByte(rest, 0)
		key := string(rest[:end])
		rest = rest[end+1:]
		end = bytes.IndexByte(rest, 0)
		updates[presenceKey{scope, key}] = string(rest[:end])
		rest = rest[end+1:]
	}
	return updates
}

func (b *backend) removeSessionPresenceLocked(s *session) {
	values := b.presence[s.account.ID]
	for _, key := range sortedPresenceKeys(values) {
		if values[key].owner != s.id {
			continue
		}
		delete(values, key)
		b.broadcastPresenceLocked(presencePacket(s.account.ID, key, "", true), nil)
	}
	if len(values) == 0 {
		delete(b.presence, s.account.ID)
	}
}
