package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

const (
	helloMagic       = 0xdefec8ed
	deadMagic        = 0xdead
	acceptedProtocol = 0xb16b00b5
)

var (
	keyMarker1 = [4]byte{'F', 'U', 'C', 'K'}
	keyMarker2 = [4]byte{'_', 'R', 'K', 'N'}
	ivMarker1  = [4]byte{'N', 'K', 'R', '_'}
	ivMarker2  = [4]byte{'K', 'C', 'U', 'F'}
)

type direction struct {
	block cipher.Block
	iv    [aes.BlockSize]byte
}

func main() {
	listen := flag.String("listen", ":48385", "TCP address for the ZClient primary endpoint")
	upstream := flag.String("upstream", "", "optional upstream address for transparent protocol capture")
	username := flag.String("username", "", "optional display name for newly registered local accounts (default: login name)")
	accountsPath := flag.String("accounts", "accounts.json", "persistent local account file")
	flag.Parse()

	var server *backend
	if *upstream == "" {
		if *username != "" && !validName(*username) {
			log.Fatal("invalid display name")
		}
		store, err := openAccountStore(*accountsPath)
		if err != nil {
			log.Fatal(err)
		}
		server = newBackend(store, *username)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ZClient local backend listening on %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		if *upstream != "" {
			go proxyCapture(conn, *upstream)
		} else {
			go server.serve(conn)
		}
	}
}

func proxyCapture(client net.Conn, upstreamAddr string) {
	defer client.Close()
	server, err := net.DialTimeout("tcp", upstreamAddr, 10*time.Second)
	if err != nil {
		log.Printf("capture upstream: %v", err)
		return
	}
	defer server.Close()
	clientRaw, clientIn, clientProtocol, err := readHelloRaw(client)
	if err != nil {
		log.Printf("capture client hello: %v", err)
		return
	}
	if _, err = server.Write(clientRaw); err != nil {
		return
	}
	serverRaw, serverIn, serverProtocol, err := readHelloRaw(server)
	if err != nil {
		log.Printf("capture server hello: %v", err)
		return
	}
	if _, err = client.Write(serverRaw); err != nil {
		return
	}
	log.Printf("capture established client=%08x server=%08x", clientProtocol, serverProtocol)
	done := make(chan struct{}, 2)
	go capturePackets("client", client, server, clientIn, done)
	go capturePackets("server", server, client, serverIn, done)
	<-done
}

func capturePackets(label string, src net.Conn, dst net.Conn, d *direction, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	for {
		packet, raw, err := readPacketRaw(src, d)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("capture %s: %v", label, err)
			}
			return
		}
		if label == "client" && packet[0] == 4 {
			log.Printf("capture client login packet (%d bytes; contents redacted)", len(packet))
		} else {
			log.Printf("capture %s packet type=%d bytes=%d\n%s", label, packet[0], len(packet), hex.Dump(packet))
		}
		if _, err = dst.Write(raw); err != nil {
			return
		}
	}
}

func readHelloRaw(r io.Reader) ([]byte, *direction, uint32, error) {
	first := make([]byte, 32)
	if _, err := io.ReadFull(r, first); err != nil {
		return nil, nil, 0, err
	}
	d, err := directionFromClear(first[:16])
	if err != nil {
		return nil, nil, 0, err
	}
	plain := make([]byte, 16)
	cipher.NewCBCDecrypter(d.block, d.iv[:]).CryptBlocks(plain, first[16:])
	if binary.LittleEndian.Uint32(plain[4:8]) != helloMagic || binary.LittleEndian.Uint16(plain[8:10]) != deadMagic {
		return nil, nil, 0, fmt.Errorf("bad hello magic")
	}
	tailLen := int(binary.LittleEndian.Uint16(plain[10:12]))
	if tailLen < 0 || tailLen > 4096 || tailLen%16 != 0 {
		return nil, nil, 0, fmt.Errorf("bad hello tail %d", tailLen)
	}
	raw := append([]byte(nil), first...)
	last := first[16:]
	if tailLen > 0 {
		tail := make([]byte, tailLen)
		if _, err = io.ReadFull(r, tail); err != nil {
			return nil, nil, 0, err
		}
		raw = append(raw, tail...)
		last = tail[len(tail)-16:]
	}
	copy(d.iv[:], last)
	return raw, d, binary.LittleEndian.Uint32(plain[12:16]), nil
}

func readPacketRaw(r io.Reader, d *direction) ([]byte, []byte, error) {
	firstCipher := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(r, firstCipher); err != nil {
		return nil, nil, err
	}
	firstPlain := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(d.block, d.iv[:]).CryptBlocks(firstPlain, firstCipher)
	declared := int(binary.LittleEndian.Uint32(firstPlain[1:5]))
	plainLen := declared + 5
	if plainLen < 5 || plainLen > 16<<20 {
		return nil, nil, fmt.Errorf("invalid declared packet length %d", declared)
	}
	padded := (plainLen + 15) &^ 15
	packet := make([]byte, padded)
	copy(packet, firstPlain)
	raw := append([]byte(nil), firstCipher...)
	last := firstCipher
	if padded > 16 {
		rest := make([]byte, padded-16)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, nil, err
		}
		cipher.NewCBCDecrypter(d.block, firstCipher).CryptBlocks(packet[16:], rest)
		raw = append(raw, rest...)
		last = rest[len(rest)-16:]
	}
	copy(d.iv[:], last)
	return packet[:plainLen], raw, nil
}

func (b *backend) serve(conn net.Conn) {
	var current *session
	defer func() { b.endSession(current) }()
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Printf("%s connected", remote)
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	in, protocolID, err := readClientHello(conn)
	if err != nil {
		log.Printf("%s hello: %v", remote, err)
		return
	}
	log.Printf("%s AES established, protocol=%08x", remote, protocolID)

	out, err := writeServerHello(conn, acceptedProtocol)
	if err != nil {
		log.Printf("%s hello response: %v", remote, err)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	writer := newPacketWriter(conn, out)
	defer writer.close()

	for {
		// Reclaim silent or half-open connections; observed heartbeats arrive
		// every 22 seconds. Keep initial authentication more tightly bounded.
		timeout := 90 * time.Second
		if current == nil {
			timeout = 30 * time.Second
		}
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		packet, err := readPacket(conn, in)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("%s packet: %v", remote, err)
			}
			return
		}
		if packet[0] == 4 {
			log.Printf("%s client login packet received (%d bytes; contents redacted)", remote, len(packet))
		} else {
			log.Printf("%s client packet type=%d bytes=%d\n%s", remote, packet[0], len(packet), hex.Dump(packet))
		}
		if current == nil && packet[0] != 0 && packet[0] != 1 && packet[0] != 2 && packet[0] != 4 {
			log.Printf("%s rejected packet before login", remote)
			return
		}
		if packet[0] == 1 {
			if len(packet) != 14 || packet[5] != 7 {
				log.Printf("%s unsupported validation packet", remote)
				return
			}
			validation := []byte{1, 5, 0, 0, 0, 7, 0, 0, 0, 0}
			if err := writer.send(validation); err != nil {
				log.Printf("%s type-1 response: %v", remote, err)
				return
			}
			log.Printf("%s accepted protocol version 7", remote)
		} else if packet[0] == 2 && len(packet) == 10 && packet[5] == 2 {
			validation := []byte{2, 6, 0, 0, 0, 2, 7, 0, 0, 0, 0}
			copy(validation[7:], packet[6:10])
			if err := writer.send(validation); err != nil {
				log.Printf("%s nonce response: %v", remote, err)
				return
			}
			log.Printf("%s echoed validation nonce", remote)
		} else if packet[0] == 4 && current == nil {
			login, digest, err := parseLogin(packet)
			if err != nil {
				log.Printf("%s login rejected: %v", remote, err)
				return
			}
			a, err := b.accounts.login(login, digest, b.displayName)
			if err != nil {
				log.Printf("%s login rejected: %v", remote, err)
				return
			}
			current = b.startSession(a)
			b.attachWriter(current, writer)
			loginResult := loginSuccessPacket(a.Name, a.ID)
			if err := writer.send(loginResult); err != nil {
				log.Printf("%s login response: %v", remote, err)
				return
			}
			log.Printf("%s local login accepted as %q account=%d session=%d", remote, current.account.Name, current.account.ID, current.id)
		} else if packet[0] == 12 && len(packet) == 6 && packet[5] == 2 {
			gametime := gametimeResponse()
			if err := writer.send(gametime); err != nil {
				log.Printf("%s gametime response: %v", remote, err)
				return
			}
			log.Printf("%s sent captured-layout gametime response", remote)
		} else if gameID, started, ok := gametimeEvent(packet); ok {
			// These are fire-and-forget lifecycle notifications, not sync
			// requests. The payload updates its own play-time state locally.
			event := "stopped"
			b.gameEvent(current, gameID, started)
			if started {
				event = "started"
			}
			log.Printf("%s game %s id=%d (0x%x); no acknowledgment required", remote, event, gameID, gameID)
		} else if packet[0] == 18 && len(packet) >= 9 {
			gamesDB, responseKind := gamesDBResponse(packet)
			if gamesDB == nil {
				log.Printf("%s rejected GamesDB request: %s", remote, responseKind)
				continue
			}
			if err := writer.send(gamesDB); err != nil {
				log.Printf("%s GamesDB response: %v", remote, err)
				return
			}
			log.Printf("%s sent GamesDB response command=%x layout=%s bytes=%d", remote, packet[5:9], responseKind, len(gamesDB))
		} else if packet[0] == 14 && len(packet) >= 9 {
			achievements := achievementsResponse(packet)
			if err := writer.send(achievements); err != nil {
				log.Printf("%s achievements response: %v", remote, err)
				return
			}
			log.Printf("%s sent empty achievements response command=%x\n%s", remote, packet[5:9], hex.Dump(achievements))
		} else if packet[0] == 15 && len(packet) >= 9 {
			response := achievementsStatsResponse(packet)
			if err := writer.send(response); err != nil {
				log.Printf("%s achievement stats response: %v", remote, err)
				return
			}
			log.Printf("%s sent achievement stats response command=%x\n%s", remote, packet[5:9], hex.Dump(response))
		} else if packet[0] == 16 && len(packet) >= 9 {
			if err := b.handleDatastore(current, packet); err != nil {
				log.Printf("%s datastore: %v", remote, err)
				return
			}
		} else if packet[0] == 11 && len(packet) >= 8 && packet[len(packet)-1] == 0 {
			// Observed client diagnostics: two prefix bytes and a NUL-terminated
			// message. Quote the message to keep multiline dumps on one log line.
			log.Printf("%s client diagnostic prefix=%x message=%q", remote, packet[5:7], packet[7:len(packet)-1])
		} else if packet[0] == 4 {
			if len(packet) != 13 {
				log.Printf("%s unexpected login on bound session", remote)
				return
			}
			// The real client sends a separate eight-byte type-4 post-auth
			// notification after data synchronization. It has no direct response.
			log.Printf("%s accepted post-auth type-4 notification", remote)
		} else if isAuthCompleteRequest(packet) {
			current.authComplete = true
			notification := authCompleteNotification()
			if err := b.completePresenceSync(current, notification); err != nil {
				log.Printf("%s auth-complete notification: %v", remote, err)
				return
			}
			log.Printf("%s sent captured-layout auth-complete type-6 notification\n%s", remote, hex.Dump(notification))
		} else if packet[0] == 0 && len(packet) == 5 {
			// The real service emits empty type-0 packets as its application-level
			// heartbeat. Echo one for each client heartbeat to keep both watchdogs
			// active without introducing a separate timer goroutine.
			if err := writer.send([]byte{0, 0, 0, 0, 0}); err != nil {
				log.Printf("%s heartbeat response: %v", remote, err)
				return
			}
			log.Printf("%s echoed heartbeat", remote)
		} else {
			log.Printf("%s unhandled client packet type=%d payload_bytes=%d", remote, packet[0], len(packet)-5)
		}
	}
}

func isAuthCompleteRequest(packet []byte) bool {
	if len(packet) != 10 || packet[0] != 17 {
		return false
	}
	// August: command then subtype 1.
	oldLayout := packet[5] == 0x8d && packet[6] == 0x29 &&
		packet[7] == 0x37 && packet[8] == 0xa1 && packet[9] == 1
	// September: subtype 2 then the same command.
	newLayout := packet[5] == 2 && packet[6] == 0x8d &&
		packet[7] == 0x29 && packet[8] == 0x37 && packet[9] == 0xa1
	return oldLayout || newLayout
}

// gametimeEvent decodes subtype 0 (stop) or 1 (start), then a big-endian
// game ID. Verified in September payload sub_63C196E0 and its callers.
func gametimeEvent(packet []byte) (gameID uint32, started bool, ok bool) {
	if len(packet) != 10 || packet[0] != 12 ||
		binary.LittleEndian.Uint32(packet[1:5]) != 5 || packet[5] > 1 {
		return 0, false, false
	}
	return binary.BigEndian.Uint32(packet[6:10]), packet[5] == 1, true
}

// gametimeResponse preserves the captured reply to the type-12 subtype-2
// sync request: game ID, last start Unix time, last stop Unix time, cumulative
// seconds played (all big-endian uint32), then a zero game-ID terminator.
// These are captured historical values, not live local play-time tracking.
func gametimeResponse() []byte {
	return []byte{
		12, 20, 0, 0, 0,
		0x00, 0x00, 0x00, 0x66,
		0x6a, 0x8c, 0x64, 0x5a,
		0x6a, 0x8c, 0x64, 0xf0,
		0x00, 0x00, 0x13, 0x1f,
		0x00, 0x00, 0x00, 0x00,
	}
}

func achievementsStatsResponse(request []byte) []byte {
	response := []byte{15, 9, 0, 0, 0, 0, 0, 0, 0, 0x65, 0x96, 0x1e, 0x03, 0}
	copy(response[5:9], request[5:9])
	return response
}

func datastoreResponse(request []byte, accountID uint32) []byte {
	if accountID == 0 {
		return nil
	}
	if len(request) < 9 || request[0] != 16 ||
		binary.LittleEndian.Uint32(request[1:5]) != uint32(len(request)-5) {
		return nil
	}
	var response []byte
	switch binary.BigEndian.Uint32(request[5:9]) {
	case 0x68afa209: // Captured login synchronization response.
		if len(request) != 9 {
			return nil
		}
		response = make([]byte, 29)
	case 0x6258ae09:
		// September sub_63CA5530 reads account ID, uint8 scope, and one
		// NUL-terminated key, then calls sub_63CA18A0 to erase that key.
		// Unlike an update, a removal has neither a value nor a record list.
		if len(request) < 11 || bytes.IndexByte(request[10:], 0) != len(request)-11 {
			return nil
		}
		response = make([]byte, len(request)+4)
		binary.BigEndian.PutUint32(response[9:13], accountID)
		copy(response[13:], request[9:])
	case 0x834965a4:
		// September sub_63CA5530 reads an account ID, then records until EOF:
		// uint8 scope, NUL-terminated key, NUL-terminated value. The outbound
		// update already contains the records; add the authenticated account ID.
		records := request[9:]
		if len(records) == 0 {
			return nil
		}
		for remaining := records; len(remaining) > 0; {
			if len(remaining) < 3 {
				return nil
			}
			remaining = remaining[1:] // scope
			for field := 0; field < 2; field++ {
				end := bytes.IndexByte(remaining, 0)
				if end < 0 {
					return nil
				}
				remaining = remaining[end+1:]
			}
		}
		response = make([]byte, len(request)+4)
		binary.BigEndian.PutUint32(response[9:13], accountID)
		copy(response[13:], records)
	default:
		// Other commands have different readers. A generic zero-filled reply
		// can leave unread bytes and cause the client to disconnect.
		return nil
	}
	response[0] = 16
	binary.LittleEndian.PutUint32(response[1:5], uint32(len(response)-5))
	copy(response[5:9], request[5:9])
	return response
}

// This type-6 packet immediately follows the client's short type-17 auth
// completion request in the real capture. It unlocks the final telemetry
// notification; the later long type-17 hardware report has no direct reply.
func authCompleteNotification() []byte {
	return []byte{
		6, 17, 0, 0, 0,
		0xc2, 0xd3, 0xdf, 0x00,
		0xa1, 0x37, 0x29, 0x8d, 0x01,
		0x12, 0x3e, 0x06, 0x96, 0x7d, 0xe4, 0xab, 0x97,
	}
}

// achievementsResponse completes a command-oriented type-14 request with no
// result records. ZClientPayload first reads the four-byte big-endian command
// and uses it to select a handler. For AchsStartSync (89a71bba), that handler
// then consumes zero or more achievement records until the packet is empty;
// therefore the command alone is the complete empty-catalog response.
func achievementsResponse(request []byte) []byte {
	const payloadLength = 4
	response := make([]byte, 5+payloadLength)
	response[0] = 14
	binary.LittleEndian.PutUint32(response[1:5], payloadLength)
	copy(response[5:9], request[5:9])
	return response
}

// loginSuccessPacket follows the September type-4 parser (sub_63CFB800).
// The leading four bytes are connection metadata, not the account ID. After
// the one-byte login result come the account ID and two uint32 metadata values,
// then the NUL-terminated display name and email and the empty trailing fields.
func loginSuccessPacket(username string, accountID uint32) []byte {
	const fixedPrefix = 17
	const reservedTail = 13
	if username == "" {
		username = "OfflinePlayer"
	}
	if len(username) > 64 {
		username = username[:64]
	}
	email := "offline@lan"
	payloadLength := fixedPrefix + len(username) + 1 + len(email) + 1 + reservedTail
	packet := make([]byte, 5+payloadLength)
	packet[0] = 4
	binary.LittleEndian.PutUint32(packet[1:5], uint32(payloadLength))
	binary.BigEndian.PutUint32(packet[5:9], 1)           // preserve existing connection metadata
	packet[9] = 1                                        // login result: success
	binary.BigEndian.PutUint32(packet[10:14], accountID) // nonzero local account ID
	nameOffset := 5 + fixedPrefix
	copy(packet[nameOffset:], username)
	emailOffset := nameOffset + len(username) + 1
	copy(packet[emailOffset:], email)
	return packet
}

func readClientHello(r io.Reader) (*direction, uint32, error) {
	first := make([]byte, 32)
	if _, err := io.ReadFull(r, first); err != nil {
		return nil, 0, err
	}
	d, err := directionFromClear(first[:16])
	if err != nil {
		return nil, 0, err
	}
	plainFirst := make([]byte, 16)
	cipher.NewCBCDecrypter(d.block, d.iv[:]).CryptBlocks(plainFirst, first[16:32])
	if binary.LittleEndian.Uint32(plainFirst[4:8]) != helloMagic || binary.LittleEndian.Uint16(plainFirst[8:10]) != deadMagic {
		return nil, 0, fmt.Errorf("bad client hello magic")
	}
	tailLen := int(binary.LittleEndian.Uint16(plainFirst[10:12]))
	if tailLen < 0 || tailLen > 4096 || tailLen%aes.BlockSize != 0 {
		return nil, 0, fmt.Errorf("invalid hello tail length %d", tailLen)
	}
	protocolID := binary.LittleEndian.Uint32(plainFirst[12:16])
	lastCipher := first[16:32]
	if tailLen != 0 {
		tail := make([]byte, tailLen)
		if _, err := io.ReadFull(r, tail); err != nil {
			return nil, 0, err
		}
		lastCipher = append([]byte(nil), tail[len(tail)-aes.BlockSize:]...)
		iv := first[16:32]
		cipher.NewCBCDecrypter(d.block, iv).CryptBlocks(tail, tail)
	}
	copy(d.iv[:], lastCipher)
	return d, protocolID, nil
}

func writeServerHello(w io.Writer, protocolID uint32) (*direction, error) {
	clear := make([]byte, 16)
	if _, err := rand.Read(clear); err != nil {
		return nil, err
	}
	d, err := directionFromClear(clear)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 16)
	if _, err := rand.Read(plain[:4]); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(plain[4:8], helloMagic)
	binary.LittleEndian.PutUint16(plain[8:10], deadMagic)
	binary.LittleEndian.PutUint16(plain[10:12], 0)
	binary.LittleEndian.PutUint32(plain[12:16], protocolID)
	ciphertext := make([]byte, 16)
	cipher.NewCBCEncrypter(d.block, d.iv[:]).CryptBlocks(ciphertext, plain)
	copy(d.iv[:], ciphertext[len(ciphertext)-aes.BlockSize:])
	_, err = w.Write(append(clear, ciphertext...))
	return d, err
}

func writePacket(w io.Writer, d *direction, packet []byte) error {
	if len(packet) < 5 {
		return fmt.Errorf("packet is too short")
	}
	padded := (len(packet) + aes.BlockSize - 1) &^ (aes.BlockSize - 1)
	plain := make([]byte, padded)
	copy(plain, packet)
	encrypted := make([]byte, padded)
	cipher.NewCBCEncrypter(d.block, d.iv[:]).CryptBlocks(encrypted, plain)
	copy(d.iv[:], encrypted[len(encrypted)-aes.BlockSize:])
	_, err := w.Write(encrypted)
	return err
}

func directionFromClear(clear []byte) (*direction, error) {
	if len(clear) != 16 {
		return nil, fmt.Errorf("clear key material is %d bytes", len(clear))
	}
	key := make([]byte, 0, 16)
	key = append(key, clear[0:4]...)
	key = append(key, keyMarker1[:]...)
	key = append(key, clear[4:8]...)
	key = append(key, keyMarker2[:]...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var iv [aes.BlockSize]byte
	copy(iv[0:4], clear[8:12])
	copy(iv[4:8], ivMarker1[:])
	copy(iv[8:12], clear[12:16])
	copy(iv[12:16], ivMarker2[:])
	return &direction{block: block, iv: iv}, nil
}

func readPacket(r io.Reader, d *direction) ([]byte, error) {
	firstCipher := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(r, firstCipher); err != nil {
		return nil, err
	}
	firstPlain := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(d.block, d.iv[:]).CryptBlocks(firstPlain, firstCipher)
	declared := int(binary.LittleEndian.Uint32(firstPlain[1:5]))
	plainLen := declared + 5
	if plainLen < 5 || plainLen > 16<<20 {
		return nil, fmt.Errorf("invalid declared packet length %d", declared)
	}
	padded := (plainLen + aes.BlockSize - 1) &^ (aes.BlockSize - 1)
	packet := make([]byte, padded)
	copy(packet, firstPlain)
	lastCipher := firstCipher
	if padded > aes.BlockSize {
		rest := make([]byte, padded-aes.BlockSize)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, err
		}
		cipher.NewCBCDecrypter(d.block, firstCipher).CryptBlocks(packet[aes.BlockSize:], rest)
		lastCipher = rest[len(rest)-aes.BlockSize:]
	}
	copy(d.iv[:], lastCipher)
	return packet[:plainLen], nil
}
