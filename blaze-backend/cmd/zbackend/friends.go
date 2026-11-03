package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"sort"
)

const friendAddCommand uint32 = 0xb35c3185
const friendAcceptCommand uint32 = 0x41d09660
const friendStatusCommand uint32 = 0x005ef20f

// Public directory entries never contain login credentials or verifiers.
type friendAccount struct {
	ID   uint32
	Name string
}

func (s *accountStore) directory() map[uint32]friendAccount {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[uint32]friendAccount, len(s.accounts))
	for _, a := range s.accounts {
		result[a.ID] = friendAccount{a.ID, a.Name}
	}
	return result
}

func appendU32(p []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(p, v) }

func finishDatastorePacket(p []byte) []byte {
	p[0] = 16
	binary.LittleEndian.PutUint32(p[1:5], uint32(len(p)-5))
	return p
}

func friendAddPacket(a friendAccount) []byte {
	p := appendU32(make([]byte, 5), friendAddCommand)
	p = appendU32(p, a.ID)
	p = append(p, []byte(a.Name)...)
	p = append(p, 0)
	p = appendU32(p, 0) // avatar version: no download
	return finishDatastorePacket(p)
}

// Relationship 1 registers the name; the acceptance delta moves it to group 2.
func friendAcceptPacket(id uint32) []byte {
	p := appendU32(make([]byte, 5), friendAcceptCommand)
	return finishDatastorePacket(appendU32(p, id))
}

func friendStatusPacket(id uint32, online bool) []byte {
	p := appendU32(make([]byte, 5), friendStatusCommand)
	p = appendU32(p, id)
	status := byte(0)
	if online {
		status = 1
	}
	p = append(p, status)
	return finishDatastorePacket(p)
}

func (b *backend) friendIDsLocked(self uint32) []uint32 {
	ids := make([]uint32, 0, len(b.friends))
	for id := range b.friends {
		if id != self {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (b *backend) onlineFriendsLocked() map[uint32]bool {
	online := make(map[uint32]bool)
	for _, s := range b.sessions {
		if s.presenceReady && !s.offline {
			online[s.account.ID] = true
		}
	}
	return online
}

// September 63CA5530: four ID-terminated relationship groups, then an
// ID-terminated status list. The September 10 online capture places accepted
// friends in group 2. B35C3185 alone installs group 1 (pending). Names use the NUL-terminated byte-string reader
// 63E682B0; IDs and avatar versions use big-endian 32-bit readers.
func (b *backend) friendRosterLocked(s *session) ([]byte, map[uint32]bool, error) {
	ids := b.friendIDsLocked(s.account.ID)
	online := b.onlineFriendsLocked()
	games := b.activeGamesLocked()
	known := make(map[uint32]bool, len(ids))
	p := appendU32(make([]byte, 5), 0x68afa209)
	p = appendU32(p, 0) // empty relationship group 0
	p = appendU32(p, 0) // empty pending relationship group 1
	for _, id := range ids {
		p = appendU32(p, id)
		p = append(p, []byte(b.friends[id].Name)...)
		p = append(p, 0)
		p = appendU32(p, 0) // avatar version
		if len(p) > maxQueuedBytes-32 {
			return nil, nil, fmt.Errorf("friend roster exceeds output limit")
		}
	}
	p = appendU32(p, 0) // end accepted friends
	p = appendU32(p, 0) // empty group 3
	for _, id := range ids {
		p = appendU32(p, id)
		known[id] = online[id]
		if online[id] {
			p = append(p, 1)
			// game ID, game-start timestamp, extra state, uint16 scope-0
			// record count and records, uint8 scope-1 count and records.
			p = appendU32(p, games[id].ID)
			p = appendU32(p, games[id].Started)
			p = appendU32(p, 0)
			keys := sortedPresenceKeys(b.presence[id])
			for scope := byte(0); scope <= 1; scope++ {
				count := 0
				for _, key := range keys {
					if key.scope == scope {
						count++
					}
				}
				if scope == 0 {
					p = binary.BigEndian.AppendUint16(p, uint16(count))
				} else {
					p = append(p, byte(count))
				}
				for _, key := range keys {
					if key.scope != scope {
						continue
					}
					p = append(p, key.key...)
					p = append(p, 0)
					p = append(p, b.presence[id][key].value...)
					p = append(p, 0)
				}
			}
		} else {
			p = append(p, 0)
		}
	}
	p = appendU32(p, 0)
	if len(p) > maxQueuedBytes {
		return nil, nil, fmt.Errorf("friend roster exceeds output limit")
	}
	return finishDatastorePacket(p), known, nil
}

func (b *backend) sendFriendRosterLocked(s *session) error {
	p, known, err := b.friendRosterLocked(s)
	if err != nil {
		return err
	}
	if err = s.writer.send(p); err != nil {
		return err
	}
	s.knownFriends = known
	s.knownGames = make(map[uint32]uint32, len(known))
	for id, game := range b.activeGamesLocked() {
		if id != s.account.ID {
			s.knownGames[id] = game.ID
		}
	}
	log.Printf("friend roster account=%d entries=%d", s.account.ID, len(known))
	return nil
}

// Called under the same lock as subscriptions and presence mutations. New
// identities are queued before their status and before any presence update.
func (b *backend) refreshFriendsLocked() {
	online := b.onlineFriendsLocked()
	games := b.activeGamesLocked()
	for _, peer := range b.sessions {
		if !peer.presenceReady || peer.writer == nil {
			continue
		}
		for _, id := range b.friendIDsLocked(peer.account.ID) {
			was, known := peer.knownFriends[id]
			if !known {
				if err := peer.writer.send(friendAddPacket(b.friends[id])); err != nil {
					log.Printf("friend discovery: %v", err)
					break
				}
				if err := peer.writer.send(friendAcceptPacket(id)); err != nil {
					log.Printf("friend acceptance: %v", err)
					break
				}
			}
			if !known || was != online[id] {
				if err := peer.writer.send(friendStatusPacket(id, online[id])); err != nil {
					log.Printf("friend status: %v", err)
					break
				}
				if online[id] {
					for _, key := range sortedPresenceKeys(b.presence[id]) {
						if err := peer.writer.send(presencePacket(id, key, b.presence[id][key].value, false)); err != nil {
							break
						}
					}
				}
				log.Printf("friend discovery recipient=%d friend=%d online=%t new=%t", peer.account.ID, id, online[id], !known)
			}
			peer.knownFriends[id] = online[id]
			game := games[id].ID
			if game != peer.knownGames[id] {
				if err := peer.writer.send(friendGamePacket(id, game)); err != nil {
					log.Printf("friend game: %v", err)
					break
				}
				peer.knownGames[id] = game
				// A game transition clears the client's scope-0 rich presence.
				// Replay the current values after establishing the game identity.
				for _, key := range sortedPresenceKeys(b.presence[id]) {
					if online[id] && key.scope == 0 {
						if err := peer.writer.send(presencePacket(id, key, b.presence[id][key].value, false)); err != nil {
							break
						}
					}
				}
				log.Printf("friend game recipient=%d friend=%d game=%d", peer.account.ID, id, game)
			}
		}
	}
}
