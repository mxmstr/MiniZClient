package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestLoginSuccessPacket(t *testing.T) {
	packet := loginSuccessPacket("LANPlayer", 1)
	payloadLength := int(binary.LittleEndian.Uint32(packet[1:5]))
	if len(packet) != payloadLength+5 || packet[0] != 4 {
		t.Fatalf("bad type-4 header: %x", packet[:5])
	}
	payload := packet[5:]
	if payload[4] != 1 {
		t.Fatalf("bad type-4 result: %x", payload)
	}
	// The payload's success handler reads the ID after the result byte,
	// not from the leading four-byte connection metadata. A zero here
	// previously produced a successful login with no usable account ID.
	if got := binary.BigEndian.Uint32(payload[5:9]); got != 1 {
		t.Fatalf("client would read account ID %d, want 1: %x", got, payload)
	}
	if got := string(payload[17 : 17+len("LANPlayer")]); got != "LANPlayer" || payload[17+len("LANPlayer")] != 0 {
		t.Fatalf("bad display name: %q", got)
	}
	emailOffset := 17 + len("LANPlayer") + 1
	if got := string(payload[emailOffset : emailOffset+len("offline@lan")]); got != "offline@lan" {
		t.Fatalf("bad local email: %q", got)
	}
}

func TestClientHello(t *testing.T) {
	clear := []byte("0123456789abcdef")
	d, err := directionFromClear(clear)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 32)
	binary.LittleEndian.PutUint32(plain[4:8], helloMagic)
	binary.LittleEndian.PutUint16(plain[8:10], deadMagic)
	binary.LittleEndian.PutUint16(plain[10:12], 16)
	binary.LittleEndian.PutUint32(plain[12:16], 0xb16b00b5)
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(d.block, d.iv[:]).CryptBlocks(ciphertext, plain)
	wire := append(append([]byte{}, clear...), ciphertext...)

	got, protocol, err := readClientHello(bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || protocol != 0xb16b00b5 {
		t.Fatalf("protocol=%08x", protocol)
	}
}

func TestDirectionMarkers(t *testing.T) {
	d, err := directionFromClear([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	wantKey := []byte("0123FUCK4567_RKN")
	want, _ := aes.NewCipher(wantKey)
	zero := make([]byte, 16)
	a, b := make([]byte, 16), make([]byte, 16)
	d.block.Encrypt(a, zero)
	want.Encrypt(b, zero)
	if !bytes.Equal(a, b) || string(d.iv[:]) != "89abNKR_cdefKCUF" {
		t.Fatal("key or IV marker reconstruction differs")
	}
}

func TestAchievementsStartSyncResponseIsCommandOnly(t *testing.T) {
	request := []byte{14, 8, 0, 0, 0, 0x89, 0xa7, 0x1b, 0xba, 0, 0, 0, 0}
	response := achievementsResponse(request)

	want := []byte{14, 4, 0, 0, 0, 0x89, 0xa7, 0x1b, 0xba}
	if !bytes.Equal(response, want) {
		t.Fatalf("bad empty achievements response: got=%x want=%x", response, want)
	}
}

func TestCapturedPostAuthResponses(t *testing.T) {
	if want := []byte{12, 20, 0, 0, 0, 0, 0, 0, 0x66, 0x6a, 0x8c, 0x64, 0x5a, 0x6a, 0x8c, 0x64, 0xf0, 0, 0, 0x13, 0x1f, 0, 0, 0, 0}; !bytes.Equal(gametimeResponse(), want) {
		t.Fatalf("bad type-12 response: %x", gametimeResponse())
	}

	command15 := []byte{15, 12, 0, 0, 0, 0x89, 0xa7, 0x1b, 0xba, 0, 0, 0, 0, 0, 0, 0, 0}
	want15 := []byte{15, 9, 0, 0, 0, 0x89, 0xa7, 0x1b, 0xba, 0x65, 0x96, 0x1e, 0x03, 0}
	if got := achievementsStatsResponse(command15); !bytes.Equal(got, want15) {
		t.Fatalf("bad type-15 response: %x", got)
	}

	command16 := []byte{16, 4, 0, 0, 0, 0x68, 0xaf, 0xa2, 0x09}
	got16 := datastoreResponse(command16, 1)
	if len(got16) != 29 || binary.LittleEndian.Uint32(got16[1:5]) != 24 || !bytes.Equal(got16[5:9], command16[5:9]) {
		t.Fatalf("bad type-16 response: %x", got16)
	}

	want6 := []byte{6, 17, 0, 0, 0, 0xc2, 0xd3, 0xdf, 0, 0xa1, 0x37, 0x29, 0x8d, 1, 0x12, 0x3e, 0x06, 0x96, 0x7d, 0xe4, 0xab, 0x97}
	if got := authCompleteNotification(); !bytes.Equal(got, want6) {
		t.Fatalf("bad type-6 notification: %x", got)
	}
}

func TestAuthCompleteRequestLayouts(t *testing.T) {
	oldLayout := []byte{17, 5, 0, 0, 0, 0x8d, 0x29, 0x37, 0xa1, 1}
	newLayout := []byte{17, 5, 0, 0, 0, 2, 0x8d, 0x29, 0x37, 0xa1}
	if !isAuthCompleteRequest(oldLayout) {
		t.Fatal("August auth-complete layout was not recognized")
	}
	if !isAuthCompleteRequest(newLayout) {
		t.Fatal("September auth-complete layout was not recognized")
	}
	if isAuthCompleteRequest([]byte{17, 5, 0, 0, 0, 3, 0x8d, 0x29, 0x37, 0xa1}) {
		t.Fatal("unknown auth-complete subtype was accepted")
	}
}

func TestGametimeLifecyclePackets(t *testing.T) {
	for _, subtype := range []byte{0, 1} {
		packet := []byte{12, 5, 0, 0, 0, subtype, 0, 0, 0, 0x66}
		gameID, started, ok := gametimeEvent(packet)
		if !ok || gameID != 102 || started != (subtype == 1) {
			t.Fatalf("packet=%x: gameID=%d started=%v ok=%v", packet, gameID, started, ok)
		}
	}
	for _, packet := range [][]byte{
		nil,
		{12, 1, 0, 0, 0, 2}, // Sync is a separate request requiring a reply.
		{12, 5, 0, 0, 0, 2, 0, 0, 0, 0x66},
		{12, 4, 0, 0, 0, 1, 0, 0, 0, 0x66},
		{11, 5, 0, 0, 0, 1, 0, 0, 0, 0x66},
		{12, 5, 0, 0, 0, 1, 0, 0, 0},
	} {
		if _, _, ok := gametimeEvent(packet); ok {
			t.Fatalf("accepted non-lifecycle packet %x", packet)
		}
	}
}

func TestDatastorePresenceResponse(t *testing.T) {
	// Exact presence record from the Rivals trace. There is no record count
	// or terminator after the value's NUL: the client reads through EOF.
	request := append([]byte{16, 46, 0, 0, 0, 0x83, 0x49, 0x65, 0xa4},
		[]byte("\x00Z_GAME_PRESENCE\x00Patrolling in a Vanquish\x00")...)
	response := datastoreResponse(request, 1)
	want := append([]byte{16, 50, 0, 0, 0, 0x83, 0x49, 0x65, 0xa4, 0, 0, 0, 1}, request[9:]...)
	if !bytes.Equal(response, want) {
		t.Fatalf("presence response: got=%x want=%x", response, want)
	}
	// Empty values and multiple records are valid and must remain intact.
	request = append([]byte{16, 0, 0, 0, 0, 0x83, 0x49, 0x65, 0xa4}, []byte("\x00key\x00\x00\x01other\x00value\x00")...)
	binary.LittleEndian.PutUint32(request[1:5], uint32(len(request)-5))
	response = datastoreResponse(request, 1)
	if len(response) != len(request)+4 || !bytes.Equal(response[13:], request[9:]) {
		t.Fatalf("records changed: %x", response)
	}
}

func TestDatastoreRejectsUnknownAndMalformed(t *testing.T) {
	for _, request := range [][]byte{
		nil,
		{16, 4, 0, 0, 0, 1, 2, 3, 4},
		{16, 4, 0, 0, 0, 0x83, 0x49, 0x65, 0xa4},
		{16, 7, 0, 0, 0, 0x83, 0x49, 0x65, 0xa4, 0, 'k', 0},      // missing value
		{16, 8, 0, 0, 0, 0x83, 0x49, 0x65, 0xa4, 0, 'k', 0, 'v'}, // unterminated value
		{16, 8, 0, 0, 0, 0x83, 0x49, 0x65, 0xa4, 0, 0, 0, 0},     // trailing byte
		{16, 99, 0, 0, 0, 0x68, 0xaf, 0xa2, 9},
		{16, 4, 0, 0, 0, 0x62, 0x58, 0xae, 9},               // missing removal scope/key
		{16, 6, 0, 0, 0, 0x62, 0x58, 0xae, 9, 0, 'k'},       // unterminated key
		{16, 8, 0, 0, 0, 0x62, 0x58, 0xae, 9, 0, 'k', 0, 0}, // unexpected value/trailer
	} {
		if got := datastoreResponse(request, 1); got != nil {
			t.Fatalf("replied to invalid request %x with %x", request, got)
		}
	}
}

func TestDatastorePresenceRemovalResponse(t *testing.T) {
	request := append([]byte{16, 22, 0, 0, 0, 0x62, 0x58, 0xae, 9, 0}, []byte("EA_GAME_PRESENCE\x00")...)
	want := append([]byte{16, 26, 0, 0, 0, 0x62, 0x58, 0xae, 9, 0, 0, 0, 1, 0}, []byte("EA_GAME_PRESENCE\x00")...)
	if got := datastoreResponse(request, 1); !bytes.Equal(got, want) {
		t.Fatalf("removal reply: got=%x want=%x", got, want)
	}
	// Preserve scopes other than zero and do not append an empty value.
	request[9] = 1
	want[13] = 1
	if got := datastoreResponse(request, 1); !bytes.Equal(got, want) {
		t.Fatalf("scoped removal reply: got=%x want=%x", got, want)
	}
}

func TestPresenceAndDiagnosticsKeepConnectionUsable(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	store, err := openAccountStore(t.TempDir() + "/accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	b := newBackend(store, "LANPlayer")
	go func() { defer close(done); b.serve(server) }()
	defer func() { client.Close(); <-done }()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	out, err := writeServerHello(client, 0xc588f5f6)
	if err != nil {
		t.Fatal(err)
	}
	in, _, err := readClientHello(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePacket(client, out, testLoginPacket("LANPlayer", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := readPacket(client, in); err != nil {
		t.Fatal(err)
	}
	request := append([]byte{16, 46, 0, 0, 0, 0x83, 0x49, 0x65, 0xa4}, []byte("\x00Z_GAME_PRESENCE\x00Patrolling in a Vanquish\x00")...)
	if err := writePacket(client, out, request); err != nil {
		t.Fatal(err)
	}
	got, err := readPacket(client, in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, datastoreResponse(request, 1)) {
		t.Fatalf("wrong presence reply: %x", got)
	}
	removal := append([]byte{16, 22, 0, 0, 0, 0x62, 0x58, 0xae, 9, 0}, []byte("EA_GAME_PRESENCE\x00")...)
	if err := writePacket(client, out, removal); err != nil {
		t.Fatal(err)
	}
	got, err = readPacket(client, in)
	if err != nil {
		t.Fatal(err)
	}
	wantRemoval := append([]byte{16, 26, 0, 0, 0, 0x62, 0x58, 0xae, 9, 0, 0, 0, 1, 0}, []byte("EA_GAME_PRESENCE\x00")...)
	if !bytes.Equal(got, wantRemoval) {
		t.Fatalf("wrong removal reply: %x", got)
	}
	// A diagnostic is a report, not a request. The next reply must be the
	// heartbeat; this also checks framing and CBC state across both packets.
	if err := writePacket(client, out, []byte{11, 5, 0, 0, 0, 0, 0, 'o', 'k', 0}); err != nil {
		t.Fatal(err)
	}
	heartbeat := []byte{0, 0, 0, 0, 0}
	if err := writePacket(client, out, heartbeat); err != nil {
		t.Fatal(err)
	}
	got, err = readPacket(client, in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, heartbeat) {
		t.Fatalf("unexpected reply after diagnostic: %x", got)
	}
}
