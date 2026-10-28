package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func capturedSetup(t *testing.T, name string) (Packet, []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "research", "rivals", "traces", name)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxBytes*2)
	for scanner.Scan() {
		var row struct {
			Event   string `json:"event"`
			WireHex string `json:"wire_hex"`
		}
		if json.Unmarshal(scanner.Bytes(), &row) != nil || row.Event != "wire_packet" {
			continue
		}
		raw, err := hex.DecodeString(row.WireHex)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := decodePacket(raw)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Component() == 4 && packet.Command() == 20 {
			return packet, raw
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("setup packet absent")
	return Packet{}, nil
}

func TestCapturedPairAndNotification(t *testing.T) {
	a, rawA := capturedSetup(t, "rivals-DESKTOP-BSOIDFC-20260913T054739-1789278459576958800.jsonl")
	b, rawB := capturedSetup(t, "rivals-DESKTOP-5QTTFAA-20260913T054946-1789278586745351000.jsonl")
	encoded, err := a.Encode()
	if err != nil || !equalBytes(encoded, rawA) {
		t.Fatalf("codec round trip: %v", err)
	}
	r := newRegistry(90*time.Second, false, false)
	replyA, err := r.exchange("a", rawA)
	if err != nil {
		t.Fatal(err)
	}
	replyB, err := r.exchange("b", rawB)
	if err != nil {
		t.Fatal(err)
	}
	pa, err := decodePacket(replyA)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := decodePacket(replyB)
	if err != nil {
		t.Fatal(err)
	}
	ga, _ := structField(pa.Fields, "GAME")
	gb, _ := structField(pb.Fields, "GAME")
	gidA, _ := integerField(ga, "GID")
	gidB, _ := integerField(gb, "GID")
	if gidA != gidB || gidA != 0x10000 {
		t.Fatalf("game IDs %d %d", gidA, gidB)
	}
	roster, err := listField(pb.Fields, "PROS")
	if err != nil || len(roster.Items) != 2 {
		t.Fatalf("roster: %v items=%d", err, len(roster.Items))
	}
	first, _ := fieldsFromItem(roster.Items[0])
	second, _ := fieldsFromItem(roster.Items[1])
	if mustInteger(first, "SID") != 0 || mustInteger(second, "SID") != 1 || mustInteger(first, "CSID") != 0 || mustInteger(second, "CSID") != 1 {
		t.Fatal("slot assignment mismatch")
	}
	poll, err := r.poll("a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(poll) < 8 {
		t.Fatal("missing join notification")
	}
	size := int(uint32(poll[4]) | uint32(poll[5])<<8 | uint32(poll[6])<<16 | uint32(poll[7])<<24)
	notice, err := decodePacket(poll[8 : 8+size])
	if err != nil || notice.Command() != 21 {
		t.Fatalf("join notification: %v command=%d", err, notice.Command())
	}
	_ = b
}

func TestCreateOnlySetupsNeverMatchEachOther(t *testing.T) {
	_, rawA := capturedSetup(t, "rivals-DESKTOP-BSOIDFC-20260913T054739-1789278459576958800.jsonl")
	_, rawB := capturedSetup(t, "rivals-DESKTOP-5QTTFAA-20260913T054946-1789278586745351000.jsonl")
	r := newRegistry(90*time.Second, false, false)
	if _, err := r.exchangeSetup("a", rawA, false); err != nil {
		t.Fatal(err)
	}
	if _, err := r.exchangeSetup("b", rawB, false); err != nil {
		t.Fatal(err)
	}
	gameA, gameB := r.gameID("a"), r.gameID("b")
	if gameA == gameB || gameA == 0 || gameB == 0 {
		t.Fatalf("create-only game IDs = %d and %d; want distinct nonzero games", gameA, gameB)
	}
	if r.games[gameA].Matchable || r.games[gameB].Matchable {
		t.Fatal("create-only friends game was exposed to public matchmaking")
	}
	if len(r.games[gameA].Members) != 1 || len(r.games[gameB].Members) != 1 {
		t.Fatalf("create-only member counts = %d and %d; want one host each",
			len(r.games[gameA].Members), len(r.games[gameB].Members))
	}
}

func TestThirdAdmittedPlayerWaitsForMeshUpdate(t *testing.T) {
	template, _ := capturedSetup(t, "rivals-DESKTOP-BSOIDFC-20260913T054739-1789278459576958800.jsonl")
	templateRoster, err := listField(template.Fields, "PROS")
	if err != nil || len(templateRoster.Items) != 1 {
		t.Fatalf("template roster: %v", err)
	}
	templatePlayer, err := fieldsFromItem(templateRoster.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	localMachineID := setupPlayerMachineID(t, templatePlayer)
	setup := func(pid, cong int64) []byte {
		packet, err := clonePacket(template)
		if err != nil {
			t.Fatal(err)
		}
		gameFields, _ := structField(packet.Fields, "GAME")
		for _, role := range []string{"PHST", "THST"} {
			host, _ := structField(gameFields, role)
			_ = setInteger(host, "HPID", pid)
			_ = setInteger(host, "CONG", cong)
		}
		roster, _ := listField(packet.Fields, "PROS")
		player, _ := fieldsFromItem(roster.Items[0])
		_ = setInteger(player, "PID", pid)
		_ = setInteger(player, "CONG", cong)
		_ = setInteger(player, "UID", pid)
		raw, err := packet.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	r := newRegistry(time.Minute, false, false)
	firstReply, err := r.exchange("a", setup(1001, 2001))
	if err != nil {
		t.Fatal(err)
	}
	firstPacket, err := decodePacket(firstReply)
	if err != nil {
		t.Fatal(err)
	}
	if got := setupHostMachineID(t, firstPacket); got != localMachineID {
		t.Fatalf("host sees GAME.HNET MACI %d; want its local MACI %d", got, localMachineID)
	}
	if got := setupRosterMachineIDs(t, firstPacket); len(got) != 1 || got[0] != localMachineID {
		t.Fatalf("host roster MACIs = %v; want [%d]", got, localMachineID)
	}
	if got := setupPlayerMachineID(t, r.peers["a"].Player); got != localMachineID {
		t.Fatalf("stored host MACI = %d; want captured MACI %d", got, localMachineID)
	}
	if got := gameHostMachineID(t, r.games[r.gameID("a")].Data); got != localMachineID {
		t.Fatalf("stored GAME.HNET MACI = %d; want captured MACI %d", got, localMachineID)
	}

	secondReply, err := r.exchange("b", setup(1002, 2002))
	if err != nil {
		t.Fatal(err)
	}
	secondPacket, err := decodePacket(secondReply)
	if err != nil {
		t.Fatal(err)
	}
	if got := setupHostMachineID(t, secondPacket); got != localMachineID {
		t.Fatalf("player 2 sees host GAME.HNET MACI %d; want captured MACI %d", got, localMachineID)
	}
	if got := setupRosterMachineIDs(t, secondPacket); len(got) != 2 || got[0] != localMachineID || got[1] != localMachineID {
		t.Fatalf("player 2 roster MACIs = %v; want captured MACI %d for both local instances", got, localMachineID)
	}
	_ = r.drain("a")
	thirdRequest := setup(1003, 2003)
	thirdReply, err := r.exchange("c", thirdRequest)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := decodePacket(thirdReply)
	if err != nil {
		t.Fatal(err)
	}
	roster, err := listField(packet.Fields, "PROS")
	if err != nil || len(roster.Items) != 3 {
		t.Fatalf("third player roster has %d members, error %v; want 3", len(roster.Items), err)
	}
	if got := setupRosterMachineIDs(t, packet); len(got) != 3 || got[0] != localMachineID || got[1] != localMachineID || got[2] != localMachineID {
		t.Fatalf("player 3 roster MACIs = %v; want captured MACI %d for every local instance", got, localMachineID)
	}
	if got := setupHostMachineID(t, packet); got != localMachineID {
		t.Fatalf("player 3 sees host GAME.HNET MACI %d; want captured MACI %d", got, localMachineID)
	}
	replayedReply, err := r.exchange("c", thirdRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayedReply, thirdReply) {
		t.Fatal("replayed setup did not return the cached recipient-specific reply")
	}
	gameID := r.gameID("c")
	if r.games[gameID].Completed[1003] {
		t.Fatal("third admitted player completed before a connected mesh update")
	}
	for _, key := range []string{"a", "b"} {
		events := r.drain(key)
		if len(events) != 1 {
			t.Fatalf("existing peer %s received %d events, want only the join event", key, len(events))
		}
		_, got, messageType, _ := blazeMetadata(events[0])
		if got != 21 || messageType != 2 {
			t.Fatalf("peer %s event = command %d type %d; want command 21 type 2", key, got, messageType)
		}
		notice, err := decodePacket(events[0])
		if err != nil {
			t.Fatal(err)
		}
		joined, err := structField(notice.Fields, "PDAT")
		if err != nil {
			t.Fatal(err)
		}
		if machineID := setupPlayerMachineID(t, joined); machineID != localMachineID {
			t.Fatalf("peer %s join MACI = %d; want captured MACI %d", key, machineID, localMachineID)
		}
	}
	thirdEvents := r.drain("c")
	if len(thirdEvents) != 0 {
		t.Fatalf("third peer received %d premature completion events, want 0", len(thirdEvents))
	}
}

func setupRosterMachineIDs(t *testing.T, packet Packet) []int64 {
	t.Helper()
	roster, err := listField(packet.Fields, "PROS")
	if err != nil {
		t.Fatal(err)
	}
	result := make([]int64, 0, len(roster.Items))
	for _, item := range roster.Items {
		player, err := fieldsFromItem(item)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, setupPlayerMachineID(t, player))
	}
	return result
}

func setupPlayerMachineID(t *testing.T, player []Field) int64 {
	t.Helper()
	network, err := unionField(player, "PNET")
	if err != nil || network.Index != 2 || network.Field == nil || network.Field.Kind != 3 {
		t.Fatalf("player network address: %v", err)
	}
	pair, ok := network.Field.Value.([]Field)
	if !ok {
		t.Fatal("player network value is not an address pair")
	}
	machineID, err := integerField(pair, "MACI")
	if err != nil {
		t.Fatal(err)
	}
	return machineID
}

func setupHostMachineID(t *testing.T, packet Packet) int64 {
	t.Helper()
	gameFields, err := structField(packet.Fields, "GAME")
	if err != nil {
		t.Fatal(err)
	}
	return gameHostMachineID(t, gameFields)
}

func gameHostMachineID(t *testing.T, gameFields []Field) int64 {
	t.Helper()
	hosts, err := listField(gameFields, "HNET")
	if err != nil || hosts.Kind != 3 || len(hosts.Items) != 1 {
		t.Fatalf("host network list: %v", err)
	}
	host, ok := hosts.Items[0].(LegacyAddress)
	if !ok {
		t.Fatal("host network item is not a legacy address")
	}
	machineID, err := integerField(host.Fields, "MACI")
	if err != nil {
		t.Fatal(err)
	}
	return machineID
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestHTTPContract(t *testing.T) {
	_, raw := capturedSetup(t, "rivals-DESKTOP-BSOIDFC-20260913T054739-1789278459576958800.jsonl")
	token := "test-token-0123456789"
	handler := &server{registry: newRegistry(90*time.Second, false, false), token: token}
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	post := func(path, auth string, body []byte) *http.Response {
		req, err := http.NewRequest(http.MethodPost, httpServer.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Rivals-Token", auth)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	denied := post("/exchange/a", "wrong-token-12345", raw)
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("auth status %d", denied.StatusCode)
	}
	_ = denied.Body.Close()
	accepted := post("/exchange/a", token, raw)
	if accepted.StatusCode != http.StatusOK {
		t.Fatalf("exchange status %d", accepted.StatusCode)
	}
	_ = accepted.Body.Close()
	invalid := post("/poll/a?after=99", token, nil)
	if invalid.StatusCode != http.StatusConflict {
		t.Fatalf("cursor status %d", invalid.StatusCode)
	}
	_ = invalid.Body.Close()
}
