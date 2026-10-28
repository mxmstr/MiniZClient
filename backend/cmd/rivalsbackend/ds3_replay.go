package main

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

//go:embed ds3_replay.json
var ds3ReplayJSON []byte

type ds3ReplayJSONFrame struct {
	Direction string `json:"direction"`
	Frame     string `json:"frame"`
}

type ds3ReplayFrame struct {
	direction string
	frame     []byte
}

type ds3ReplayServer struct {
	frames []ds3ReplayFrame
}

type ds3ReplaySession struct {
	server       *ds3ReplayServer
	cursor       int
	correlations map[uint32]uint32
}

func newDS3ReplayServer() (*ds3ReplayServer, error) {
	var encoded []ds3ReplayJSONFrame
	if err := json.Unmarshal(ds3ReplayJSON, &encoded); err != nil {
		return nil, fmt.Errorf("decode DS3 replay transcript: %w", err)
	}
	if len(encoded) == 0 {
		return nil, fmt.Errorf("DS3 replay transcript is empty")
	}
	server := &ds3ReplayServer{frames: make([]ds3ReplayFrame, 0, len(encoded))}
	for index, item := range encoded {
		if item.Direction != "client_to_server" && item.Direction != "server_to_client" {
			return nil, fmt.Errorf("DS3 replay frame %d has invalid direction %q", index, item.Direction)
		}
		frame, err := hex.DecodeString(item.Frame)
		if err != nil {
			return nil, fmt.Errorf("decode DS3 replay frame %d: %w", index, err)
		}
		if len(frame) < 12 {
			return nil, fmt.Errorf("DS3 replay frame %d is shorter than a Fire2 header", index)
		}
		server.frames = append(server.frames, ds3ReplayFrame{direction: item.Direction, frame: frame})
	}
	if server.frames[0].direction != "client_to_server" {
		return nil, fmt.Errorf("DS3 replay transcript does not begin with a client request")
	}
	return server, nil
}

func (s *ds3ReplayServer) newSession() *ds3ReplaySession {
	return &ds3ReplaySession{server: s, correlations: make(map[uint32]uint32)}
}

// accept consumes the next captured client request and returns every captured
// server frame that preceded the following client request. This preserves the
// real client's pipelining: several DS3 RPC replies arrive only after a later
// request has already been sent.
func (s *ds3ReplaySession) accept(request []byte) ([][]byte, bool, error) {
	if s.cursor >= len(s.server.frames) {
		return nil, false, nil
	}
	expected := s.server.frames[s.cursor]
	if expected.direction != "client_to_server" {
		return nil, false, fmt.Errorf("DS3 replay cursor %d points at an unconsumed server frame", s.cursor)
	}
	expectedComponent, expectedCommand, expectedType, capturedCorrelation := blazeMetadata(expected.frame)
	component, command, messageType, liveCorrelation := blazeMetadata(request)
	if component != expectedComponent || command != expectedCommand || messageType != expectedType {
		return nil, false, nil
	}
	s.correlations[capturedCorrelation] = liveCorrelation
	s.cursor++

	var replies [][]byte
	for s.cursor < len(s.server.frames) && s.server.frames[s.cursor].direction == "server_to_client" {
		frame := append([]byte(nil), s.server.frames[s.cursor].frame...)
		_, _, responseType, capturedResponseCorrelation := blazeMetadata(frame)
		if responseType == 1 || responseType == 3 {
			liveResponseCorrelation, ok := s.correlations[capturedResponseCorrelation]
			if !ok {
				return nil, false, fmt.Errorf("DS3 replay response at cursor %d refers to unseen correlation %d", s.cursor, capturedResponseCorrelation)
			}
			setBlazeCorrelation(frame, liveResponseCorrelation)
		}
		replies = append(replies, frame)
		s.cursor++
	}
	return replies, true, nil
}
