package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

type row struct {
	Event  string `json:"event"`
	Socket uint64 `json:"socket"`
	Result int    `json:"result"`
	Data   string `json:"data"`
}
type frame struct {
	Direction          string
	Raw                []byte
	Component, Command uint16
	Type               byte
	Correlation        uint32
}
type entry struct {
	Request string   `json:"request"`
	Replies []string `json:"replies"`
}

func frames(data []byte) ([][]byte, bool) {
	var out [][]byte
	for len(data) > 0 {
		if len(data) < 12 {
			return nil, false
		}
		flags := data[9] >> 4
		size, h := int(data[0])<<8|int(data[1]), 12
		if flags&1 != 0 {
			if len(data) < 14 {
				return nil, false
			}
			size |= (int(data[12])<<8 | int(data[13])) << 16
			h += 2
		}
		if flags&2 != 0 {
			if flags&8 != 0 {
				h += 8
			} else {
				h += 4
			}
		} else if flags&8 != 0 {
			return nil, false
		}
		if size < 0 || h+size > len(data) {
			return nil, false
		}
		messageType := data[8] >> 4
		// ZClient uses private components in the 0x7800 range for the
		// authentication/session notifications sent around the standard Blaze
		// login reply. Rejecting components above 0x100 silently discarded those
		// frames from the replay corpus and left the game polling pre-auth forever.
		if messageType > 3 {
			return nil, false
		}
		out = append(out, append([]byte(nil), data[:h+size]...))
		data = data[h+size:]
	}
	return out, len(out) > 0
}
func meta(raw []byte) (uint16, uint16, byte, uint32) {
	return uint16(raw[2])<<8 | uint16(raw[3]), uint16(raw[4])<<8 | uint16(raw[5]), raw[8] >> 4, (uint32(raw[9]&15) << 16) | uint32(raw[10])<<8 | uint32(raw[11])
}
func normalize(raw []byte) []byte {
	out := append([]byte(nil), raw...)
	out[9] &= 0xf0
	out[10] = 0
	out[11] = 0
	return out
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: rivalsreplaygen TRACE SOCKET OUTPUT")
		os.Exit(2)
	}
	socket, err := strconv.ParseUint(os.Args[2], 10, 64)
	if err != nil {
		panic(err)
	}
	input, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer input.Close()
	var ordered []frame
	scan := bufio.NewScanner(input)
	scan.Buffer(make([]byte, 4096), 2<<20)
	for scan.Scan() {
		var r row
		if json.Unmarshal(scan.Bytes(), &r) != nil || r.Socket != socket || r.Result <= 0 || r.Data == "" || (r.Event != "network_send" && r.Event != "network_recv") {
			continue
		}
		data, e := hex.DecodeString(r.Data)
		if e != nil {
			continue
		}
		parts, ok := frames(data)
		if !ok {
			continue
		}
		for _, raw := range parts {
			c, cmd, t, corr := meta(raw)
			ordered = append(ordered, frame{r.Event, raw, c, cmd, t, corr})
		}
	}
	if err := scan.Err(); err != nil {
		panic(err)
	}
	entries := []entry{}
	pending := map[uint32]int{}
	last := -1
	for _, f := range ordered {
		if f.Direction == "network_recv" && f.Type == 0 {
			entries = append(entries, entry{Request: hex.EncodeToString(normalize(f.Raw))})
			last = len(entries) - 1
			pending[f.Correlation] = last
			continue
		}
		if f.Direction != "network_send" {
			continue
		}
		target := -1
		if f.Type == 1 || f.Type == 3 {
			if index, ok := pending[f.Correlation]; ok {
				target = index
				delete(pending, f.Correlation)
			}
		} else if f.Type == 2 {
			target = last
		}
		if target >= 0 {
			entries[target].Replies = append(entries[target].Replies, hex.EncodeToString(normalize(f.Raw)))
		}
	}
	out, err := os.Create(os.Args[3])
	if err != nil {
		panic(err)
	}
	defer out.Close()
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(entries); err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %d replay entries\n", len(entries))
}
