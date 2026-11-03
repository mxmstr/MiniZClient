package main

import "time"

type activeGame struct {
	ID       uint32
	Started  uint32
	sequence uint64
}

// September 63CA5530: 2E1F3C2D reads account and game ID, and stamps
// the start locally. 2B4B435F reads only account ID and clears game state.
func friendGamePacket(id, game uint32) []byte {
	command := uint32(0x2e1f3c2d)
	if game == 0 {
		command = 0x2b4b435f
	}
	p := appendU32(make([]byte, 5), command)
	p = appendU32(p, id)
	if game != 0 {
		p = appendU32(p, game)
	}
	return finishDatastorePacket(p)
}

func (b *backend) activeGamesLocked() map[uint32]activeGame {
	result := make(map[uint32]activeGame)
	for _, s := range b.sessions {
		if !s.presenceReady || s.offline {
			continue
		}
		for _, game := range s.games {
			if game.sequence > result[s.account.ID].sequence {
				result[s.account.ID] = game
			}
		}
	}
	return result
}

func (b *backend) gameEvent(s *session, id uint32, started bool) {
	if id == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sessions[s.id] != s {
		return
	}
	if started {
		if _, exists := s.games[id]; exists {
			return
		}
		b.nextGameSequence++
		s.games[id] = activeGame{id, uint32(time.Now().Unix()), b.nextGameSequence}
	} else {
		if _, exists := s.games[id]; !exists {
			return
		}
		delete(s.games, id)
	}
	b.refreshFriendsLocked()
}
