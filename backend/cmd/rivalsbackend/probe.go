package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// probeCapture is deliberately schema-free.  The first DS3 milestone is to
// preserve every live request (including fields that the current TDF decoder
// does not yet understand) while we replace the empty responses with real
// Authentication and GameManager handlers.
type probeCapture struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

type ds3ReplayClient struct {
	connection net.Conn
	remote     string
	writeMu    sync.Mutex
	lobby      *ds3LobbyClient
}

func (c *ds3ReplayClient) write(frame []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.connection.Write(frame)
	return err
}

type probeRecord struct {
	Time        time.Time `json:"time"`
	Remote      string    `json:"remote"`
	Component   uint16    `json:"component"`
	Command     uint16    `json:"command"`
	MessageType byte      `json:"message_type"`
	Correlation uint32    `json:"correlation"`
	FrameHex    string    `json:"frame_hex"`
	Fields      []Field   `json:"fields,omitempty"`
	DecodeError string    `json:"decode_error,omitempty"`
}

func (c *probeCapture) write(remote string, frame []byte) {
	component, command, messageType, correlation := blazeMetadata(frame)
	record := probeRecord{
		Time: time.Now().UTC(), Remote: remote, Component: component,
		Command: command, MessageType: messageType,
		Correlation: correlation, FrameHex: hex.EncodeToString(frame),
	}
	if packet, err := decodePacket(frame); err != nil {
		record.DecodeError = err.Error()
	} else {
		record.Fields = packet.Fields
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.encoder.Encode(record); err != nil {
		log.Printf("DS3 capture write failed: %v", err)
	}
}

func emptyBlazeSuccess(request []byte) []byte {
	component, command, _, correlation := blazeMetadata(request)
	reply := make([]byte, 12)
	reply[2], reply[3] = byte(component>>8), byte(component)
	reply[4], reply[5] = byte(command>>8), byte(command)
	reply[8] = 0x10 // response
	setBlazeCorrelation(reply, correlation)
	return reply
}

func serveBlazeProbe(listener net.Listener, config *tls.Config,
	capturePath string) error {
	file, err := os.OpenFile(capturePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	capture := &probeCapture{encoder: json.NewEncoder(file)}
	tlsListener := tls.NewListener(listener, config)
	for {
		connection, err := tlsListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handleBlazeProbe(connection, capture)
	}
}

func handleBlazeProbe(connection net.Conn, capture *probeCapture) {
	defer connection.Close()
	remote := connection.RemoteAddr().String()
	log.Printf("DS3 Blaze probe connected remote=%s", remote)
	for {
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Minute))
		frame, err := readBlazeFrame(connection)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("DS3 Blaze probe disconnected remote=%s error=%v", remote, err)
			}
			return
		}
		component, command, messageType, correlation := blazeMetadata(frame)
		capture.write(remote, frame)
		log.Printf("DS3 Blaze request component=%d command=%d type=%d correlation=%d bytes=%d",
			component, command, messageType, correlation, len(frame))
		if messageType != 0 {
			continue
		}
		if _, err := connection.Write(emptyBlazeSuccess(frame)); err != nil {
			log.Printf("DS3 Blaze probe reply failed remote=%s error=%v", remote, err)
			return
		}
	}
}

// serveDS3BlazeReplay accepts the plaintext Fire2 transport selected by the
// captured redirector's SECU=0 field. ZClient places its own local proxy at the
// advertised localhost endpoint; the standalone backend replaces that proxy,
// so TLS termination is required only on the redirector port.
func serveDS3BlazeReplay(listener net.Listener, capturePath string) error {
	file, err := os.OpenFile(capturePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	replay, err := newDS3ReplayServer()
	if err != nil {
		return err
	}
	capture := &probeCapture{encoder: json.NewEncoder(file)}
	lobbies := newDS3LobbyRegistry()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handleDS3BlazeReplay(connection, capture, replay, lobbies)
	}
}

func handleDS3BlazeReplay(connection net.Conn, capture *probeCapture, replay *ds3ReplayServer, lobbies *ds3LobbyRegistry) {
	defer connection.Close()
	remote := connection.RemoteAddr().String()
	session := replay.newSession()
	client := &ds3ReplayClient{connection: connection, remote: remote}
	client.lobby = &ds3LobbyClient{key: remote, send: client.write}
	defer lobbies.leave(client.lobby)
	log.Printf("DS3 plaintext Blaze replay connected remote=%s transcript_frames=%d", remote, len(replay.frames))
	for {
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Minute))
		request, err := readBlazeFrame(connection)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("DS3 plaintext Blaze replay disconnected remote=%s error=%v", remote, err)
			}
			return
		}
		component, command, messageType, correlation := blazeMetadata(request)
		capture.write("plaintext:"+remote+":request", request)
		log.Printf("DS3 plaintext Blaze request component=%d command=%d type=%d correlation=%d bytes=%d cursor=%d/%d",
			component, command, messageType, correlation, len(request), session.cursor, len(replay.frames))
		if messageType != 0 {
			continue
		}
		if component == 1 && command == 152 {
			identity, identityErr := localBlazeIdentity(request)
			if identityErr != nil {
				log.Printf("DS3 authentication identity from %s is invalid: %v", remote, identityErr)
				return
			}
			client.lobby.identity = identity
			log.Printf("DS3 authenticated local identity remote=%s name=%s id=%d", remote, identity.name, identity.id)
		}
		replies, matched, replayErr := session.accept(request)
		if replayErr != nil {
			log.Printf("DS3 plaintext Blaze replay failed remote=%s error=%v", remote, replayErr)
			return
		}
		if !matched {
			replies = [][]byte{emptyBlazeSuccess(request)}
			if replayErr != nil {
				log.Printf("DS3 dynamic reply failed remote=%s component=%d command=%d error=%v", remote, component, command, replayErr)
				return
			}
			log.Printf("DS3 plaintext Blaze transcript mismatch remote=%s cursor=%d; using dynamic fallback component=%d command=%d correlation=%d",
				remote, session.cursor, component, command, correlation)
		}
		for index, reply := range replies {
			personalized, _, personalizeErr := personalizeReplayReply(reply, time.Now().Unix(), client.lobby.identity)
			if personalizeErr != nil {
				log.Printf("DS3 replay personalization failed remote=%s error=%v", remote, personalizeErr)
				return
			}
			if client.lobby.gameID != 0 {
				personalized, personalizeErr = rewriteDS3FrameGameID(personalized, client.lobby.gameID)
				if personalizeErr != nil {
					log.Printf("DS3 replay game-id rewrite failed remote=%s error=%v", remote, personalizeErr)
					return
				}
			}
			replies[index] = personalized
		}
		if component == 4 && command == 1 {
			replies, replayErr = lobbies.registerCreate(client.lobby, replies)
			if replayErr != nil {
				log.Printf("DS3 public lobby registration failed remote=%s error=%v", remote, replayErr)
				return
			}
			if client.lobby.gameID != 0 {
				log.Printf("DS3 public lobby registered remote=%s game=%d player=%s", remote, client.lobby.gameID, client.lobby.identity.name)
			}
		}
		var lobbyMatch *ds3LobbyMatch
		var removedHost *ds3LobbyClient
		var removedNotice []byte
		var gameDeliveries []ds3LobbyDelivery
		if component == 4 && command == 3 {
			stateDeliveries, stateErr := lobbies.updateState(client.lobby, request, !matched)
			if stateErr != nil {
				log.Printf("DS3 state update failed remote=%s error=%v", remote, stateErr)
				return
			}
			gameDeliveries = append(gameDeliveries, stateDeliveries...)
			log.Printf("DS3 game state accepted remote=%s game=%d deliveries=%d", remote, client.lobby.gameID, len(stateDeliveries))
		}
		if component == 4 && command == 8 {
			attributeDeliveries, attributeErr := lobbies.updatePlayerAttributes(client.lobby, request, !matched)
			if attributeErr != nil {
				log.Printf("DS3 player-attribute update failed remote=%s error=%v", remote, attributeErr)
				return
			}
			gameDeliveries = append(gameDeliveries, attributeDeliveries...)
			log.Printf("DS3 player attributes accepted remote=%s game=%d deliveries=%d", remote, client.lobby.gameID, len(attributeDeliveries))
		}
		if component == 4 && command == 7 {
			attributeDeliveries, attributeErr := lobbies.updateGameAttributes(client.lobby, request, !matched)
			if attributeErr != nil {
				log.Printf("DS3 game-attribute update failed remote=%s error=%v", remote, attributeErr)
				return
			}
			gameDeliveries = append(gameDeliveries, attributeDeliveries...)
			log.Printf("DS3 game attributes accepted remote=%s game=%d deliveries=%d", remote, client.lobby.gameID, len(attributeDeliveries))
		}
		if component == 4 && command == 13 {
			lobbyMatch, replayErr = lobbies.match(client.lobby, request)
			if replayErr != nil {
				log.Printf("DS3 public matchmaking failed remote=%s error=%v", remote, replayErr)
				return
			}
			if lobbyMatch != nil {
				matchResponse, responseErr := ds3MatchmakingResponse(request, lobbyMatch.matchID)
				if responseErr != nil {
					log.Printf("DS3 matchmaking response failed remote=%s error=%v", remote, responseErr)
					return
				}
				replies = [][]byte{matchResponse, lobbyMatch.setup}
				log.Printf("DS3 public matchmaking selected game=%d match=%d remote=%s player=%s", client.lobby.gameID, lobbyMatch.matchID, remote, client.lobby.identity.name)
			} else {
				log.Printf("DS3 public matchmaking found no available game remote=%s", remote)
			}
		}
		if component == 4 && command == 11 {
			removePacket, decodeErr := decodePacket(request)
			if decodeErr != nil {
				log.Printf("DS3 remove-player decode failed remote=%s error=%v", remote, decodeErr)
				return
			}
			reason, reasonErr := integerField(removePacket.Fields, "REAS")
			if reasonErr != nil {
				log.Printf("DS3 remove-player reason missing remote=%s error=%v", remote, reasonErr)
				return
			}
			removedHost, removedNotice, replayErr = lobbies.removePlayer(client.lobby, reason)
			if replayErr != nil {
				log.Printf("DS3 remove-player failed remote=%s error=%v", remote, replayErr)
				return
			}
			log.Printf("DS3 player left matched game remote=%s player=%s reason=%d", remote, client.lobby.identity.name, reason)
		}
		if component == 4 && command == 29 {
			meshDeliveries, meshErr := lobbies.updateMesh(client.lobby, request)
			if meshErr != nil {
				log.Printf("DS3 mesh update failed remote=%s error=%v", remote, meshErr)
				return
			}
			gameDeliveries = append(gameDeliveries, meshDeliveries...)
			log.Printf("DS3 mesh update accepted remote=%s game=%d deliveries=%d", remote, client.lobby.gameID, len(meshDeliveries))
		}
		for _, reply := range replies {
			if err := client.write(reply); err != nil {
				log.Printf("DS3 plaintext Blaze replay write failed remote=%s error=%v", remote, err)
				return
			}
			capture.write("plaintext:"+remote+":reply", reply)
			replyComponent, replyCommand, replyType, replyCorrelation := blazeMetadata(reply)
			log.Printf("DS3 plaintext Blaze replay sent component=%d command=%d type=%d correlation=%d bytes=%d cursor=%d/%d",
				replyComponent, replyCommand, replyType, replyCorrelation, len(reply),
				session.cursor, len(replay.frames))
		}
		if lobbyMatch != nil && lobbyMatch.host != nil && lobbyMatch.host.send != nil {
			if err := lobbyMatch.host.send(lobbyMatch.hostNotice); err != nil {
				log.Printf("DS3 host join notification failed host=%s error=%v", lobbyMatch.host.key, err)
			} else {
				capture.write("plaintext:"+lobbyMatch.host.key+":reply", lobbyMatch.hostNotice)
				log.Printf("DS3 public lobby notified host=%s game=%d", lobbyMatch.host.key, client.lobby.gameID)
			}
		}
		if removedHost != nil && removedHost.send != nil && len(removedNotice) != 0 {
			if err := removedHost.send(removedNotice); err != nil {
				log.Printf("DS3 host removal notification failed host=%s error=%v", removedHost.key, err)
			} else {
				capture.write("plaintext:"+removedHost.key+":reply", removedNotice)
			}
		}
		for _, delivery := range gameDeliveries {
			if delivery.client == nil || delivery.client.send == nil {
				continue
			}
			for _, frame := range delivery.frames {
				if err := delivery.client.send(frame); err != nil {
					log.Printf("DS3 game notification failed target=%s error=%v", delivery.client.key, err)
					break
				}
				capture.write("plaintext:"+delivery.client.key+":reply", frame)
				replyComponent, replyCommand, replyType, _ := blazeMetadata(frame)
				log.Printf("DS3 game notification sent target=%s component=%d command=%d type=%d", delivery.client.key, replyComponent, replyCommand, replyType)
			}
		}
	}
}
