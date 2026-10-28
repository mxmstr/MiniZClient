package main

import "testing"

func ds3CreateRepliesForTest(t *testing.T, identity *blazeIdentity) [][]byte {
	t.Helper()
	replay, err := newDS3ReplayServer()
	if err != nil {
		t.Fatal(err)
	}
	session := replay.newSession()
	for session.cursor < len(replay.frames) {
		request := replay.frames[session.cursor].frame
		replies, matched, acceptErr := session.accept(request)
		if acceptErr != nil || !matched {
			t.Fatalf("accept create transcript: matched=%t err=%v", matched, acceptErr)
		}
		component, command, _, _ := blazeMetadata(request)
		if component != 4 || command != 1 {
			continue
		}
		for index, reply := range replies {
			personalized, _, personalizeErr := personalizeReplayReply(reply, 1800000000, identity)
			if personalizeErr != nil {
				t.Fatal(personalizeErr)
			}
			replies[index] = personalized
		}
		return replies
	}
	t.Fatal("DS3 transcript has no create-game request")
	return nil
}

func TestDS3PublicLobbyMatchesSecondIdentity(t *testing.T) {
	registry := newDS3LobbyRegistry()
	hostIdentity := &blazeIdentity{name: "host", token: []byte("ZLOCAL1:686f7374"), id: 10001}
	joinIdentity := &blazeIdentity{name: "joiner", token: []byte("ZLOCAL1:6a6f696e6572"), id: 10002}
	host := &ds3LobbyClient{key: "host", identity: hostIdentity}
	created, err := registry.registerCreate(host, ds3CreateRepliesForTest(t, hostIdentity))
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 2 || host.gameID == 0 {
		t.Fatalf("create replies=%d game=%d", len(created), host.gameID)
	}

	setup, err := decodePacket(created[1])
	if err != nil {
		t.Fatal(err)
	}
	roster, err := listField(setup.Fields, "PROS")
	if err != nil || len(roster.Items) != 1 {
		t.Fatalf("host roster invalid: items=%d err=%v", len(roster.Items), err)
	}
	hostPlayer, err := fieldsFromItem(roster.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	network, err := fieldAt(hostPlayer, "PNET", 6)
	if err != nil {
		t.Fatal(err)
	}
	matchRequest := Packet{
		Header: []byte{0, 0, 0, 4, 0, 13, 0, 0, 0, 0, 0, 7},
		Fields: []Field{*network},
	}
	matchRaw, err := matchRequest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	joiner := &ds3LobbyClient{key: "joiner", identity: joinIdentity}
	match, err := registry.match(joiner, matchRaw)
	if err != nil {
		t.Fatal(err)
	}
	if match == nil || match.host != host || joiner.gameID != host.gameID {
		t.Fatalf("bad match: %#v host_game=%d join_game=%d", match, host.gameID, joiner.gameID)
	}
	matchResponse, err := ds3MatchmakingResponse(matchRaw, match.matchID)
	if err != nil {
		t.Fatal(err)
	}
	matchResponsePacket, err := decodePacket(matchResponse)
	if err != nil {
		t.Fatal(err)
	}
	responseMatchID, err := integerField(matchResponsePacket.Fields, "MSID")
	if err != nil || responseMatchID != match.matchID {
		t.Fatalf("response MSID=%d err=%v, want %d", responseMatchID, err, match.matchID)
	}
	matchSetup, err := decodePacket(match.setup)
	if err != nil {
		t.Fatal(err)
	}
	if matchSetup.Component() != 4 || matchSetup.Command() != 20 || matchSetup.MessageType() != 2 {
		t.Fatalf("bad setup metadata: component=%d command=%d type=%d", matchSetup.Component(), matchSetup.Command(), matchSetup.MessageType())
	}
	reason, err := unionField(matchSetup.Fields, "REAS")
	if err != nil || reason.Index != 3 || reason.Field == nil {
		t.Fatalf("match reason invalid: %#v err=%v", reason, err)
	}
	matchedRoster, err := listField(matchSetup.Fields, "PROS")
	if err != nil || len(matchedRoster.Items) != 2 {
		t.Fatalf("matched roster invalid: items=%d err=%v", len(matchedRoster.Items), err)
	}
	joinedPlayer, err := fieldsFromItem(matchedRoster.Items[1])
	if err != nil {
		t.Fatal(err)
	}
	if pid, pidErr := integerField(joinedPlayer, "PID"); pidErr != nil || pid != joinIdentity.id {
		t.Fatalf("joiner PID=%d err=%v, want %d", pid, pidErr, joinIdentity.id)
	}
	name, err := bytesField(joinedPlayer, "NAME")
	if err != nil || string(name) != joinIdentity.name {
		t.Fatalf("joiner name=%q err=%v", name, err)
	}
	hostSlot, err := integerField(hostPlayer, "SID")
	if err != nil {
		t.Fatal(err)
	}
	joinerSlot, err := integerField(joinedPlayer, "SID")
	if err != nil || joinerSlot == hostSlot {
		t.Fatalf("host SID=%d joiner SID=%d err=%v", hostSlot, joinerSlot, err)
	}
	reasonFields, ok := reason.Field.Value.([]Field)
	if !ok {
		t.Fatalf("match reason payload has type %T", reason.Field.Value)
	}
	reasonMatchID, err := integerField(reasonFields, "MSID")
	if err != nil || reasonMatchID != responseMatchID {
		t.Fatalf("setup MSID=%d err=%v, response MSID=%d", reasonMatchID, err, responseMatchID)
	}
	if _, err = fieldAt(reasonFields, "TTM"); err == nil {
		t.Fatal("DS3 matchmaking context unexpectedly contains Blaze 4 TTM field")
	}
	hostNotice, err := decodePacket(match.hostNotice)
	if err != nil {
		t.Fatal(err)
	}
	if hostNotice.Command() != 21 || hostNotice.MessageType() != 2 {
		t.Fatalf("bad host notice command=%d type=%d", hostNotice.Command(), hostNotice.MessageType())
	}
	meshRequest, err := (Packet{
		Header: []byte{0, 0, 0, 4, 0, 29, 0, 0, 0, 0, 0, 11},
		Fields: []Field{
			{Tag: "GID", Kind: 0, Value: host.gameID},
			{Tag: "TARG", Kind: 4, Value: List{Kind: 3, Items: []any{
				[]Field{
					{Tag: "FLGS", Kind: 0, Value: int64(0)},
					{Tag: "PID", Kind: 0, Value: joinIdentity.id},
					{Tag: "STAT", Kind: 0, Value: int64(2)},
				},
			}}},
		},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := registry.updateMesh(host, meshRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("mesh update produced %d client deliveries, want 2", len(deliveries))
	}
	for _, delivery := range deliveries {
		if len(delivery.frames) != 2 {
			t.Fatalf("mesh delivery for %s has %d frames", delivery.client.key, len(delivery.frames))
		}
		_, stateCommand, stateType, _ := blazeMetadata(delivery.frames[0])
		_, completeCommand, completeType, _ := blazeMetadata(delivery.frames[1])
		if stateCommand != 116 || stateType != 2 || completeCommand != 30 || completeType != 2 {
			t.Fatalf("mesh commands = %d/%d types=%d/%d", stateCommand, completeCommand, stateType, completeType)
		}
	}
	attributeRequest, err := (Packet{
		Header: []byte{0, 0, 0, 4, 0, 8, 0, 0, 0, 0, 0, 12},
		Fields: []Field{
			{Tag: "ATTR", Kind: 5, Value: MapValue{KeyKind: 1, ValueKind: 1, Pairs: []Pair{{Key: []byte("AWAITING_JOIN"), Value: []byte("0")}}}},
			{Tag: "GID", Kind: 0, Value: host.gameID},
			{Tag: "PID", Kind: 0, Value: joinIdentity.id},
		},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	attributeDeliveries, err := registry.updatePlayerAttributes(joiner, attributeRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(attributeDeliveries) != 2 {
		t.Fatalf("attribute update produced %d client deliveries, want 2", len(attributeDeliveries))
	}
	for _, delivery := range attributeDeliveries {
		if len(delivery.frames) != 1 {
			t.Fatalf("attribute delivery for %s has %d frames", delivery.client.key, len(delivery.frames))
		}
		_, command, messageType, correlation := blazeMetadata(delivery.frames[0])
		if command != 90 || messageType != 2 || correlation != 0 {
			t.Fatalf("attribute notification command=%d type=%d correlation=%d", command, messageType, correlation)
		}
	}
	stateRequest, err := (Packet{
		Header: []byte{0, 0, 0, 4, 0, 3, 0, 0, 0, 0, 0, 13},
		Fields: []Field{
			{Tag: "GID", Kind: 0, Value: host.gameID},
			{Tag: "GSTA", Kind: 0, Value: int64(131)},
		},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	stateDeliveries, err := registry.updateState(host, stateRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(stateDeliveries) != 2 {
		t.Fatalf("state update produced %d client deliveries, want 2", len(stateDeliveries))
	}
	for _, delivery := range stateDeliveries {
		_, command, messageType, correlation := blazeMetadata(delivery.frames[0])
		if command != 100 || messageType != 2 || correlation != 0 {
			t.Fatalf("state notification command=%d type=%d correlation=%d", command, messageType, correlation)
		}
	}
	gameAttributeRequest, err := (Packet{
		Header: []byte{0, 0, 0, 4, 0, 7, 0, 0, 0, 0, 0, 14},
		Fields: []Field{
			{Tag: "ATTR", Kind: 5, Value: MapValue{KeyKind: 1, ValueKind: 1, Pairs: []Pair{{Key: []byte("GAME_STATUS"), Value: []byte("$UIMenu_InProgress")}}}},
			{Tag: "GID", Kind: 0, Value: host.gameID},
		},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	gameAttributeDeliveries, err := registry.updateGameAttributes(host, gameAttributeRequest, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(gameAttributeDeliveries) != 2 {
		t.Fatalf("game-attribute update produced %d client deliveries, want 2", len(gameAttributeDeliveries))
	}
	for _, delivery := range gameAttributeDeliveries {
		_, command, messageType, correlation := blazeMetadata(delivery.frames[0])
		if command != 80 || messageType != 2 || correlation != 0 {
			t.Fatalf("game-attribute notification command=%d type=%d correlation=%d", command, messageType, correlation)
		}
	}
	registry.mu.Lock()
	storedAttributes, err := fieldAt(registry.games[host.gameID].game, "ATTR", 5)
	registry.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	storedMap := storedAttributes.Value.(MapValue)
	foundGameStatus := false
	for _, pair := range storedMap.Pairs {
		key, keyOK := pair.Key.([]byte)
		value, valueOK := pair.Value.([]byte)
		if keyOK && valueOK && string(key) == "GAME_STATUS" && string(value) == "$UIMenu_InProgress" {
			foundGameStatus = true
		}
	}
	if !foundGameStatus {
		t.Fatal("updated GAME_STATUS was not persisted")
	}
	removedHost, removedNotice, err := registry.removePlayer(joiner, 6)
	if err != nil {
		t.Fatal(err)
	}
	if removedHost != host || len(removedNotice) == 0 || joiner.gameID != 0 {
		t.Fatalf("remove did not release match: host=%p notice=%d game=%d", removedHost, len(removedNotice), joiner.gameID)
	}
	thirdIdentity := &blazeIdentity{name: "third", token: []byte("ZLOCAL1:7468697264"), id: 10003}
	third := &ds3LobbyClient{key: "third", identity: thirdIdentity}
	rematch, err := registry.match(third, matchRaw)
	if err != nil || rematch == nil {
		t.Fatalf("released slot could not be rematched: match=%#v err=%v", rematch, err)
	}
}

func TestDS3FrameGameIDRewriteCoversStateNotification(t *testing.T) {
	request, err := (Packet{
		Header: []byte{0, 0, 0, 4, 0, 3, 0, 0, 0, 0, 0, 9},
		Fields: []Field{
			{Tag: "GID", Kind: 0, Value: int64(3493)},
			{Tag: "GSTA", Kind: 0, Value: int64(130)},
		},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	replies, err := advanceGameStateReplies(request)
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := rewriteDS3FrameGameID(replies[1], 0x30000)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := decodePacket(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	gameID, err := integerField(packet.Fields, "GID")
	if err != nil || gameID != 0x30000 {
		t.Fatalf("state notification GID=%d err=%v", gameID, err)
	}
}
