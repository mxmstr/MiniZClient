package main

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ds3LobbyRegistry supplies the state that the finite DS3 startup recording
// cannot contain: a game created by one live client must be discoverable by a
// later StartMatchmaking request from another live client.
type ds3LobbyRegistry struct {
	mu          sync.Mutex
	nextGameID  int64
	nextMatchID int64
	games       map[int64]*ds3Lobby
}

type ds3Lobby struct {
	id        int64
	host      *ds3LobbyClient
	game      []Field
	players   [][]Field
	members   []*ds3LobbyClient
	completed map[int64]bool
	capacity  int
}

type ds3LobbyClient struct {
	key      string
	identity *blazeIdentity
	gameID   int64
	send     func([]byte) error
}

type ds3LobbyMatch struct {
	setup      []byte
	host       *ds3LobbyClient
	hostNotice []byte
	matchID    int64
}

type ds3LobbyDelivery struct {
	client *ds3LobbyClient
	frames [][]byte
}

func newDS3LobbyRegistry() *ds3LobbyRegistry {
	return &ds3LobbyRegistry{
		nextGameID:  0x30000,
		nextMatchID: 1,
		games:       make(map[int64]*ds3Lobby),
	}
}

func ds3MatchmakingResponse(request []byte, matchID int64) ([]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	header := append([]byte(nil), packet.Header...)
	header[6], header[7] = 0, 0
	header[8] = header[8]&0x0f | 0x10
	return (Packet{Header: header, Fields: []Field{
		{Tag: "MSID", Kind: 0, Value: matchID},
	}}).Encode()
}

func rewriteDS3FrameGameID(raw []byte, gameID int64) ([]byte, error) {
	packet, err := decodePacket(raw)
	if err != nil {
		return nil, err
	}
	rewriteIntegerTag(packet.Fields, "GID", gameID)
	return packet.Encode()
}

func rewriteIntegerTag(fields []Field, tag string, value int64) {
	var rewriteValue func(byte, any) any
	rewriteValue = func(kind byte, valueToRewrite any) any {
		switch kind {
		case 3:
			if nested, ok := valueToRewrite.([]Field); ok {
				rewriteIntegerTag(nested, tag, value)
				return nested
			}
		case 4:
			if list, ok := valueToRewrite.(List); ok {
				for index, item := range list.Items {
					switch typed := item.(type) {
					case []Field:
						rewriteIntegerTag(typed, tag, value)
						list.Items[index] = typed
					case LegacyAddress:
						rewriteIntegerTag(typed.Fields, tag, value)
						list.Items[index] = typed
					}
				}
				return list
			}
		case 5:
			if mapped, ok := valueToRewrite.(MapValue); ok {
				for index := range mapped.Pairs {
					mapped.Pairs[index].Key = rewriteValue(mapped.KeyKind, mapped.Pairs[index].Key)
					mapped.Pairs[index].Value = rewriteValue(mapped.ValueKind, mapped.Pairs[index].Value)
				}
				return mapped
			}
		case 6:
			if union, ok := valueToRewrite.(Union); ok && union.Field != nil {
				union.Field.Value = rewriteValue(union.Field.Kind, union.Field.Value)
				return union
			}
		case 7:
			if variable, ok := valueToRewrite.(Variable); ok && variable.Field != nil {
				variable.Field.Value = rewriteValue(variable.Field.Kind, variable.Field.Value)
				return variable
			}
		}
		return valueToRewrite
	}
	for index := range fields {
		field := &fields[index]
		if field.Tag == tag && field.Kind == 0 {
			field.Value = value
		}
		field.Value = rewriteValue(field.Kind, field.Value)
	}
}

func rewriteDS3Player(fields []Field, identity *blazeIdentity) {
	if identity == nil {
		return
	}
	identityTags := map[string]bool{
		"AID": true, "BLID": true, "BUID": true, "CONG": true,
		"HPID": true, "HSES": true, "OGHI": true, "PID": true,
		"UID": true, "USID": true,
	}
	var walk func([]Field)
	walk = func(current []Field) {
		for index := range current {
			field := &current[index]
			if field.Kind == 0 && identityTags[field.Tag] {
				field.Value = identity.id
			}
			if field.Kind == 1 && (field.Tag == "NAME" || field.Tag == "DSNM") {
				field.Value = []byte(identity.name)
			}
			switch nested := field.Value.(type) {
			case []Field:
				walk(nested)
				field.Value = nested
			case List:
				for itemIndex, item := range nested.Items {
					if itemFields, ok := item.([]Field); ok {
						walk(itemFields)
						nested.Items[itemIndex] = itemFields
					}
				}
				field.Value = nested
			case Union:
				if nested.Field != nil {
					if itemFields, ok := nested.Field.Value.([]Field); ok {
						walk(itemFields)
						nested.Field.Value = itemFields
					}
				}
				field.Value = nested
			}
		}
	}
	walk(fields)
}

func replaceField(fields []Field, replacement Field) error {
	for index := range fields {
		if fields[index].Tag == replacement.Tag {
			fields[index] = replacement
			return nil
		}
	}
	return fmt.Errorf("missing %s", replacement.Tag)
}

func ds3Capacity(game []Field) int {
	capacity, err := listField(game, "CAP")
	if err != nil || capacity.Kind != 0 || len(capacity.Items) == 0 {
		return 2
	}
	value, ok := capacity.Items[0].(int64)
	if !ok || value < 2 || value > 8 {
		return 2
	}
	return int(value)
}

// registerCreate rewrites the captured create-game reply/setup with a unique
// live game id and stores the setup as the public matchmaking source.
func (r *ds3LobbyRegistry) registerCreate(client *ds3LobbyClient, replies [][]byte) ([][]byte, error) {
	if client == nil || client.identity == nil {
		return nil, errors.New("DS3 create game before authentication")
	}
	cloned := make([][]byte, len(replies))
	var setup Packet
	setupIndex := -1

	r.mu.Lock()
	defer r.mu.Unlock()
	gameID := r.nextGameID
	r.nextGameID++
	for index, raw := range replies {
		packet, err := decodePacket(raw)
		if err != nil {
			return nil, err
		}
		rewriteIntegerTag(packet.Fields, "GID", gameID)
		encoded, err := packet.Encode()
		if err != nil {
			return nil, err
		}
		cloned[index] = encoded
		if packet.Component() == 4 && packet.Command() == 20 && packet.MessageType() == 2 {
			setup, setupIndex = packet, index
		}
	}
	if setupIndex < 0 {
		return nil, errors.New("DS3 create replay omitted game setup notification")
	}
	gameFields, err := structField(setup.Fields, "GAME")
	if err != nil {
		return nil, err
	}
	presence, err := integerField(gameFields, "PRES")
	if err != nil {
		return nil, err
	}
	if presence == 0 {
		return cloned, nil
	}
	roster, err := listField(setup.Fields, "PROS")
	if err != nil || roster.Kind != 3 || len(roster.Items) != 1 {
		return nil, errors.New("DS3 create setup has invalid player roster")
	}
	hostPlayer, err := fieldsFromItem(roster.Items[0])
	if err != nil {
		return nil, err
	}
	gameCopy, err := cloneFields(gameFields)
	if err != nil {
		return nil, err
	}
	hostCopy, err := cloneFields(hostPlayer)
	if err != nil {
		return nil, err
	}
	r.games[gameID] = &ds3Lobby{
		id: gameID, host: client, game: gameCopy,
		players: [][]Field{hostCopy}, members: []*ds3LobbyClient{client},
		completed: make(map[int64]bool), capacity: ds3Capacity(gameCopy),
	}
	client.gameID = gameID
	return cloned, nil
}

func (r *ds3LobbyRegistry) updateState(client *ds3LobbyClient, request []byte, broadcast bool) ([]ds3LobbyDelivery, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	gameID, err := integerField(packet.Fields, "GID")
	if err != nil {
		return nil, err
	}
	state, err := integerField(packet.Fields, "GSTA")
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if client == nil || client.gameID != gameID {
		return nil, errors.New("DS3 state update for foreign game")
	}
	game := r.games[gameID]
	if game == nil || game.host != client {
		return nil, errors.New("DS3 state update from non-host")
	}
	if err = setInteger(game.game, "GSTA", state); err != nil {
		return nil, err
	}
	if !broadcast {
		return nil, nil
	}
	notice, err := notification(100, packet.Fields)
	if err != nil {
		return nil, err
	}
	deliveries := make([]ds3LobbyDelivery, 0, len(game.members))
	for _, member := range game.members {
		deliveries = append(deliveries, ds3LobbyDelivery{client: member, frames: [][]byte{notice}})
	}
	return deliveries, nil
}

// updatePlayerAttributes persists the attributes used by the DS3 lobby UI and
// mirrors Blaze's NotifyPlayerAttribChange to every member. Merely acknowledging
// command 8 leaves the host's roster in an intermediate joining state, which
// prevents the UI from issuing AdvanceGameState when Start Game is clicked.
func (r *ds3LobbyRegistry) updatePlayerAttributes(client *ds3LobbyClient, request []byte, broadcast bool) ([]ds3LobbyDelivery, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	gameID, err := integerField(packet.Fields, "GID")
	if err != nil {
		return nil, err
	}
	playerID, err := integerField(packet.Fields, "PID")
	if err != nil {
		return nil, err
	}
	attribute, err := fieldAt(packet.Fields, "ATTR", 5)
	if err != nil {
		return nil, err
	}
	attributeCopy, err := cloneFields([]Field{*attribute})
	if err != nil {
		return nil, err
	}
	attributeCopy[0].Tag = "PATT"

	r.mu.Lock()
	defer r.mu.Unlock()
	if client == nil || client.identity == nil || client.gameID != gameID || client.identity.id != playerID {
		return nil, errors.New("DS3 player-attribute update for foreign player")
	}
	game := r.games[gameID]
	if game == nil {
		return nil, errors.New("DS3 player-attribute update for missing game")
	}
	var player []Field
	for _, candidate := range game.players {
		candidateID, candidateErr := integerField(candidate, "PID")
		if candidateErr == nil && candidateID == playerID {
			player = candidate
			break
		}
	}
	if player == nil {
		return nil, errors.New("DS3 player-attribute update for player outside roster")
	}
	if err = replaceField(player, attributeCopy[0]); err != nil {
		player = append(player, attributeCopy[0])
		for index, candidate := range game.players {
			candidateID, candidateErr := integerField(candidate, "PID")
			if candidateErr == nil && candidateID == playerID {
				game.players[index] = player
				break
			}
		}
	}
	if !broadcast {
		return nil, nil
	}
	notice, err := notification(90, packet.Fields)
	if err != nil {
		return nil, err
	}
	deliveries := make([]ds3LobbyDelivery, 0, len(game.members))
	for _, member := range game.members {
		deliveries = append(deliveries, ds3LobbyDelivery{client: member, frames: [][]byte{notice}})
	}
	return deliveries, nil
}

func mergeByteMapField(fields []Field, tag string, update MapValue) error {
	target, err := fieldAt(fields, tag, 5)
	if err != nil {
		return err
	}
	current, ok := target.Value.(MapValue)
	if !ok || current.KeyKind != update.KeyKind || current.ValueKind != update.ValueKind {
		return fmt.Errorf("incompatible %s map", tag)
	}
	if current.KeyKind != 1 {
		return fmt.Errorf("unsupported %s key kind %d", tag, current.KeyKind)
	}
	for _, replacement := range update.Pairs {
		replacementKey, ok := replacement.Key.([]byte)
		if !ok {
			return fmt.Errorf("invalid %s map key", tag)
		}
		replaced := false
		for index, existing := range current.Pairs {
			existingKey, keyOK := existing.Key.([]byte)
			if keyOK && bytes.Equal(existingKey, replacementKey) {
				current.Pairs[index] = replacement
				replaced = true
				break
			}
		}
		if !replaced {
			current.Pairs = append(current.Pairs, replacement)
		}
	}
	target.Value = current
	return nil
}

// updateGameAttributes mirrors SetGameAttributes as NotifyGameAttribChange.
// DS3 changes GAME_STATUS immediately after the host advances to IN_GAME; the
// joining client cannot leave its loading barrier until it receives this map.
func (r *ds3LobbyRegistry) updateGameAttributes(client *ds3LobbyClient, request []byte, broadcast bool) ([]ds3LobbyDelivery, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	gameID, err := integerField(packet.Fields, "GID")
	if err != nil {
		return nil, err
	}
	attribute, err := fieldAt(packet.Fields, "ATTR", 5)
	if err != nil {
		return nil, err
	}
	attributeMap, ok := attribute.Value.(MapValue)
	if !ok {
		return nil, errors.New("invalid DS3 game-attribute map")
	}
	attributeCopy, err := cloneFields([]Field{*attribute})
	if err != nil {
		return nil, err
	}
	attributeMap = attributeCopy[0].Value.(MapValue)

	r.mu.Lock()
	defer r.mu.Unlock()
	if client == nil || client.gameID != gameID {
		return nil, errors.New("DS3 game-attribute update for foreign game")
	}
	game := r.games[gameID]
	if game == nil || game.host != client {
		return nil, errors.New("DS3 game-attribute update from non-host")
	}
	if err = mergeByteMapField(game.game, "ATTR", attributeMap); err != nil {
		return nil, err
	}
	if !broadcast {
		return nil, nil
	}
	notice, err := notification(80, packet.Fields)
	if err != nil {
		return nil, err
	}
	deliveries := make([]ds3LobbyDelivery, 0, len(game.members))
	for _, member := range game.members {
		deliveries = append(deliveries, ds3LobbyDelivery{client: member, frames: [][]byte{notice}})
	}
	return deliveries, nil
}

func (r *ds3LobbyRegistry) match(client *ds3LobbyClient, request []byte) (*ds3LobbyMatch, error) {
	if client == nil || client.identity == nil {
		return nil, errors.New("DS3 matchmaking before authentication")
	}
	matchRequest, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	network, err := fieldAt(matchRequest.Fields, "PNET", 6)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]int64, 0, len(r.games))
	for id := range r.games {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var selected *ds3Lobby
	for _, id := range ids {
		candidate := r.games[id]
		if candidate.host != client && len(candidate.players) < candidate.capacity {
			selected = candidate
			break
		}
	}
	if selected == nil {
		return nil, nil
	}

	joiner, err := cloneFields(selected.players[0])
	if err != nil {
		return nil, err
	}
	rewriteDS3Player(joiner, client.identity)
	rewriteIntegerTag(joiner, "GID", selected.id)
	// DS3's live create-game setup numbers the first participant as SID 1.
	// Preserve that one-based convention; SID 0 is not a player slot here.
	joinerSlot := int64(1)
	for _, player := range selected.players {
		if slot, slotErr := integerField(player, "SID"); slotErr == nil {
			if slot >= joinerSlot {
				joinerSlot = slot + 1
			}
		}
	}
	_ = setInteger(joiner, "SID", joinerSlot)
	_ = setInteger(joiner, "SLOT", 0)
	_ = setInteger(joiner, "STAT", 2)
	_ = setInteger(joiner, "TIME", time.Now().UnixMicro())
	networkCopy, err := cloneFields([]Field{*network})
	if err != nil {
		return nil, err
	}
	if err = replaceField(joiner, networkCopy[0]); err != nil {
		return nil, err
	}

	gameCopy, err := cloneFields(selected.game)
	if err != nil {
		return nil, err
	}
	roster := make([]any, 0, len(selected.players)+1)
	for _, player := range selected.players {
		copyOfPlayer, cloneErr := cloneFields(player)
		if cloneErr != nil {
			return nil, cloneErr
		}
		roster = append(roster, copyOfPlayer)
	}
	joinerCopy, err := cloneFields(joiner)
	if err != nil {
		return nil, err
	}
	roster = append(roster, joinerCopy)
	matchID := r.nextMatchID
	r.nextMatchID++
	setup, err := notification(20, []Field{
		{Tag: "GAME", Kind: 3, Value: gameCopy},
		{Tag: "PROS", Kind: 4, Value: List{Kind: 3, Items: roster}},
		{Tag: "REAS", Kind: 6, Value: Union{Index: 3, Field: &Field{
			Tag: "VALU", Kind: 3, Value: []Field{
				{Tag: "FIT", Kind: 0, Value: int64(100)},
				{Tag: "MAXF", Kind: 0, Value: int64(100)},
				{Tag: "MSID", Kind: 0, Value: matchID},
				{Tag: "RSLT", Kind: 0, Value: int64(2)},
				{Tag: "USID", Kind: 0, Value: client.identity.id},
			},
		}}},
	})
	if err != nil {
		return nil, err
	}
	hostJoiner, err := cloneFields(joiner)
	if err != nil {
		return nil, err
	}
	hostNotice, err := notification(21, []Field{
		{Tag: "GID", Kind: 0, Value: selected.id},
		{Tag: "PDAT", Kind: 3, Value: hostJoiner},
	})
	if err != nil {
		return nil, err
	}
	selected.players = append(selected.players, joiner)
	selected.members = append(selected.members, client)
	client.gameID = selected.id
	return &ds3LobbyMatch{
		setup: setup, host: selected.host, hostNotice: hostNotice, matchID: matchID,
	}, nil
}

func (r *ds3LobbyRegistry) updateMesh(client *ds3LobbyClient, request []byte) ([]ds3LobbyDelivery, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	gameID, err := integerField(packet.Fields, "GID")
	if err != nil {
		return nil, err
	}
	targets, err := listField(packet.Fields, "TARG")
	if err != nil || targets.Kind != 3 {
		return nil, errors.New("invalid DS3 mesh target list")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if client == nil || client.gameID != gameID {
		return nil, errors.New("DS3 mesh update for foreign game")
	}
	game := r.games[gameID]
	if game == nil {
		return nil, errors.New("DS3 mesh update for missing game")
	}
	deliveriesByClient := make(map[*ds3LobbyClient][][]byte)
	for _, item := range targets.Items {
		status, fieldsErr := fieldsFromItem(item)
		if fieldsErr != nil {
			return nil, fieldsErr
		}
		pid, pidErr := integerField(status, "PID")
		state, stateErr := integerField(status, "STAT")
		if pidErr != nil || stateErr != nil {
			return nil, errors.New("invalid DS3 mesh target")
		}
		if state != 2 || game.completed[pid] {
			continue
		}
		var player []Field
		for _, candidate := range game.players {
			candidatePID, candidateErr := integerField(candidate, "PID")
			if candidateErr == nil && candidatePID == pid {
				player = candidate
				break
			}
		}
		if player == nil {
			return nil, errors.New("DS3 mesh target is not in game roster")
		}
		_ = setInteger(player, "STAT", 4)
		stateNotice, noticeErr := notification(116, []Field{
			{Tag: "GID", Kind: 0, Value: gameID},
			{Tag: "PID", Kind: 0, Value: pid},
			{Tag: "STAT", Kind: 0, Value: int64(4)},
		})
		if noticeErr != nil {
			return nil, noticeErr
		}
		completeNotice, noticeErr := notification(30, []Field{
			{Tag: "GID", Kind: 0, Value: gameID},
			{Tag: "PID", Kind: 0, Value: pid},
		})
		if noticeErr != nil {
			return nil, noticeErr
		}
		for _, member := range game.members {
			deliveriesByClient[member] = append(deliveriesByClient[member], stateNotice, completeNotice)
		}
		game.completed[pid] = true
	}
	deliveries := make([]ds3LobbyDelivery, 0, len(deliveriesByClient))
	for _, member := range game.members {
		if frames := deliveriesByClient[member]; len(frames) != 0 {
			deliveries = append(deliveries, ds3LobbyDelivery{client: member, frames: frames})
		}
	}
	return deliveries, nil
}

func (r *ds3LobbyRegistry) leave(client *ds3LobbyClient) {
	if client == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	game := r.games[client.gameID]
	if game == nil {
		return
	}
	if game.host == client {
		delete(r.games, game.id)
	} else if client.identity != nil {
		for index, player := range game.players {
			pid, err := integerField(player, "PID")
			if err == nil && pid == client.identity.id {
				game.players = append(game.players[:index], game.players[index+1:]...)
				break
			}
		}
		for index, member := range game.members {
			if member == client {
				game.members = append(game.members[:index], game.members[index+1:]...)
				break
			}
		}
	}
	client.gameID = 0
}

func (r *ds3LobbyRegistry) removePlayer(client *ds3LobbyClient, reason int64) (*ds3LobbyClient, []byte, error) {
	if client == nil || client.identity == nil {
		return nil, nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	game := r.games[client.gameID]
	if game == nil {
		return nil, nil, nil
	}
	gameID := game.id
	if game.host == client {
		delete(r.games, game.id)
		client.gameID = 0
		return nil, nil, nil
	}
	for index, player := range game.players {
		pid, err := integerField(player, "PID")
		if err == nil && pid == client.identity.id {
			game.players = append(game.players[:index], game.players[index+1:]...)
			break
		}
	}
	for index, member := range game.members {
		if member == client {
			game.members = append(game.members[:index], game.members[index+1:]...)
			break
		}
	}
	client.gameID = 0
	notice, err := notification(40, []Field{
		{Tag: "CNTX", Kind: 0, Value: int64(0)},
		{Tag: "GID", Kind: 0, Value: gameID},
		{Tag: "PID", Kind: 0, Value: client.identity.id},
		{Tag: "REAS", Kind: 0, Value: reason},
	})
	if err != nil {
		return nil, nil, err
	}
	return game.host, notice, nil
}
