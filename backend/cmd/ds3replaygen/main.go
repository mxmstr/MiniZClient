package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
)

const maxFrameBody = 16 << 20

type captureRecord struct {
	Event     string `json:"event"`
	Sequence  uint64 `json:"sequence"`
	Direction string `json:"direction"`
	State     uint64 `json:"state"`
	DataHex   string `json:"data_hex"`
}

type transcriptFrame struct {
	Direction string `json:"direction"`
	Frame     string `json:"frame"`
}

type decodedFrame struct {
	sequence uint64
	state    uint64
	frame    transcriptFrame
}

type streamKey struct {
	state     uint64
	direction string
}

func frameSize(data []byte) (int, bool, bool) {
	if len(data) < 12 {
		return 0, false, false
	}
	component := uint16(data[2])<<8 | uint16(data[3])
	command := uint16(data[4])<<8 | uint16(data[5])
	messageType := data[8] >> 4
	flags := data[9] >> 4
	if component == 0 || component > 0x7fff || command == 0 || messageType > 3 {
		return 0, false, true
	}
	headerSize := 12
	bodySize := int(data[0])<<8 | int(data[1])
	if flags&1 != 0 {
		if len(data) < 14 {
			return 0, false, false
		}
		bodySize |= (int(data[12])<<8 | int(data[13])) << 16
		headerSize += 2
	}
	if flags&2 != 0 {
		if flags&8 != 0 {
			headerSize += 8
		} else {
			headerSize += 4
		}
	} else if flags&8 != 0 {
		return 0, false, true
	}
	if bodySize > maxFrameBody {
		return 0, false, true
	}
	total := headerSize + bodySize
	if len(data) < total {
		return total, false, false
	}
	return total, true, false
}

func main() {
	input := flag.String("input", "", "format-4 recorder JSONL")
	output := flag.String("output", "ds3_replay.json", "output transcript JSON")
	requestedState := flag.Uint64("state", 0, "plaintext state to export (auto-selects the state with the most frames when zero)")
	flag.Parse()
	if *input == "" {
		fmt.Fprintln(os.Stderr, "-input is required")
		os.Exit(2)
	}

	file, err := os.Open(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer file.Close()

	streams := make(map[streamKey][]byte)
	var frames []decodedFrame
	counts := make(map[uint64]int)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 32<<20)
	for scanner.Scan() {
		var record captureRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil || record.Event != "plaintext_io" {
			continue
		}
		chunk, err := hex.DecodeString(record.DataHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sequence %d: invalid data_hex: %v\n", record.Sequence, err)
			os.Exit(1)
		}
		key := streamKey{state: record.State, direction: record.Direction}
		streams[key] = append(streams[key], chunk...)
		for len(streams[key]) >= 12 {
			size, complete, invalid := frameSize(streams[key])
			if invalid {
				streams[key] = streams[key][1:]
				continue
			}
			if !complete {
				break
			}
			frame := append([]byte(nil), streams[key][:size]...)
			streams[key] = streams[key][size:]
			frames = append(frames, decodedFrame{
				sequence: record.Sequence,
				state:    record.State,
				frame: transcriptFrame{
					Direction: record.Direction,
					Frame:     hex.EncodeToString(frame),
				},
			})
			counts[record.State]++
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	state := *requestedState
	if state == 0 {
		for candidate, count := range counts {
			if count > counts[state] {
				state = candidate
			}
		}
	}
	if state == 0 || counts[state] == 0 {
		fmt.Fprintln(os.Stderr, "no Fire2 plaintext frames found")
		os.Exit(1)
	}
	sort.SliceStable(frames, func(i, j int) bool { return frames[i].sequence < frames[j].sequence })
	selected := make([]transcriptFrame, 0, counts[state])
	for _, frame := range frames {
		if frame.state == state {
			selected = append(selected, frame.frame)
		}
	}

	encoded, err := json.MarshalIndent(selected, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d frames from plaintext state %d to %s\n", len(selected), state, *output)
}
