package main

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestDS3ReplayTranscript(t *testing.T) {
	server, err := newDS3ReplayServer()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(server.frames), 48; got != want {
		t.Fatalf("transcript has %d frames, want %d", got, want)
	}
	session := server.newSession()
	for cursor := 0; cursor < len(server.frames); {
		request := server.frames[cursor]
		if request.direction != "client_to_server" {
			t.Fatalf("frame %d is %s before accept", cursor, request.direction)
		}
		cursor++
		var expected [][]byte
		for cursor < len(server.frames) && server.frames[cursor].direction == "server_to_client" {
			expected = append(expected, server.frames[cursor].frame)
			cursor++
		}
		replies, matched, err := session.accept(request.frame)
		if err != nil {
			t.Fatalf("accept at frame %d: %v", cursor, err)
		}
		if !matched {
			t.Fatalf("request before frame %d did not match", cursor)
		}
		if len(replies) != len(expected) {
			t.Fatalf("request before frame %d returned %d replies, want %d", cursor, len(replies), len(expected))
		}
		for index := range replies {
			if !bytes.Equal(replies[index], expected[index]) {
				t.Fatalf("request before frame %d reply %d differs from transcript", cursor, index)
			}
		}
	}
	if session.cursor != len(server.frames) {
		t.Fatalf("replay stopped at %d/%d", session.cursor, len(server.frames))
	}
}

func TestDS3ReplayRewritesDelayedCorrelations(t *testing.T) {
	server, err := newDS3ReplayServer()
	if err != nil {
		t.Fatal(err)
	}
	session := server.newSession()
	correlations := make(map[uint32]uint32)
	for cursor := 0; cursor < len(server.frames); {
		item := server.frames[cursor]
		if item.direction != "client_to_server" {
			t.Fatalf("frame %d is %s before accept", cursor, item.direction)
		}
		request := append([]byte(nil), item.frame...)
		_, _, _, captured := blazeMetadata(request)
		live := captured + 0x100
		setBlazeCorrelation(request, live)
		correlations[captured] = live
		cursor++
		var expected [][]byte
		for cursor < len(server.frames) && server.frames[cursor].direction == "server_to_client" {
			expected = append(expected, server.frames[cursor].frame)
			cursor++
		}
		replies, matched, err := session.accept(request)
		if err != nil || !matched {
			t.Fatalf("accept component/command request: matched=%t err=%v", matched, err)
		}
		if len(replies) != len(expected) {
			t.Fatalf("got %d replies, want %d", len(replies), len(expected))
		}
		for index, reply := range replies {
			_, _, messageType, correlation := blazeMetadata(reply)
			_, _, _, capturedReply := blazeMetadata(expected[index])
			if messageType != 1 && messageType != 3 {
				if !bytes.Equal(reply, expected[index]) {
					t.Fatalf("notification %d changed", index)
				}
				continue
			}
			if want := correlations[capturedReply]; correlation != want {
				t.Fatalf("response correlation=%d, want %d (captured %d)", correlation, want, capturedReply)
			}
			normalized := append([]byte(nil), reply...)
			setBlazeCorrelation(normalized, capturedReply)
			if !bytes.Equal(normalized, expected[index]) {
				t.Fatalf("response %d changed outside its correlation", index)
			}
		}
	}
}

func TestDS3ReplayMismatchDoesNotAdvance(t *testing.T) {
	server, err := newDS3ReplayServer()
	if err != nil {
		t.Fatal(err)
	}
	session := server.newSession()
	request := append([]byte(nil), server.frames[0].frame...)
	request[5]++
	if replies, matched, err := session.accept(request); err != nil || matched || replies != nil {
		t.Fatalf("mismatch returned replies=%d matched=%t err=%v", len(replies), matched, err)
	}
	if session.cursor != 0 {
		t.Fatalf("mismatch advanced cursor to %d", session.cursor)
	}
}

func TestDS3PlaintextReplayTransport(t *testing.T) {
	replay, err := newDS3ReplayServer()
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	var captured bytes.Buffer
	capture := &probeCapture{encoder: json.NewEncoder(&captured)}
	go handleDS3BlazeReplay(server, capture, replay, newDS3LobbyRegistry())
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(replay.frames[0].frame); err != nil {
		t.Fatal(err)
	}
	reply, err := readBlazeFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, replay.frames[1].frame) {
		t.Fatal("plaintext replay changed the first captured response")
	}
	if !bytes.Contains(captured.Bytes(), []byte(`"component":9`)) {
		t.Fatalf("plaintext request was not captured: %s", captured.String())
	}
}
