package main

import (
	"encoding/binary"
	"fmt"
)

// Minimal empty-profile schemas. Native plate and challenge consumers parse
// scope=value keys for unlocks/challenges and need descriptor storage even when
// there are no rows. The selected plate is unscoped: FUN_004c2a30 obtains its
// result via FUN_00bfde30's exact No_Scope_Defined lookup, then FUN_006e3520
// unconditionally dereferences it. A scoped key here causes a null read at +0xc.
// These are not production progression schemas and never fabricate earned data.
// Scope names below are local compatibility conventions: native consumers parse
// the numeric suffix, while the SDK matches the advertised scope/result key.
var nfs13StatsScopes = map[string]string{
	"license_plate":             "",
	"license_plate_unlock":      "license_plate",
	"online_challenge":          "online_challenge",
	"online_concours_challenge": "online_challenge",
}

func nfs13StatsReplies(request []byte) ([][]byte, error) {
	p, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	header := append([]byte(nil), p.Header...)
	header[6], header[7], header[8] = 0, 0, 0x10
	reject := func() ([][]byte, error) {
		header[7], header[8] = 1, 0x30 // Explicit RPC failure, never abandon the socket.
		reply, err := (Packet{Header: header}).Encode()
		return [][]byte{reply}, err
	}
	name, err := bytesField(p.Fields, "NAME")
	if err != nil {
		return reject()
	}
	scope, known := nfs13StatsScopes[string(name)]
	if !known {
		return reject()
	}
	text := func(tag, value string) Field { return Field{Tag: tag, Kind: 1, Value: []byte(value)} }
	if p.Command() == 4 {
		var scopePairs []Pair
		if scope != "" {
			scopePairs = []Pair{{Key: []byte(scope), Value: int64(0)}}
		}
		descriptor := []Field{
			text("CATG", string(name)), text("DFLT", "0"), text("FRMT", "%d"),
			text("LDSC", "value"), text("NAME", "value"), text("SDSC", "value"),
			{Tag: "TYPE", Kind: 0, Value: int64(0)},
		}
		reply, err := (Packet{Header: header, Fields: []Field{
			text("CNAM", string(name)), text("DESC", string(name)),
			{Tag: "ETYP", Kind: 8, Value: ObjectID{30722, 1}},
			{Tag: "KSUM", Kind: 5, Value: MapValue{KeyKind: 1, ValueKind: 0, Pairs: scopePairs}},
			text("NAME", string(name)),
			{Tag: "STAT", Kind: 4, Value: List{Kind: 3, Items: []any{descriptor}}},
		}}).Encode()
		return [][]byte{reply}, err
	}
	if p.Command() != 16 {
		return reject()
	}
	vid, err := integerField(p.Fields, "VID")
	if err != nil {
		return reject()
	}
	scopeValue := int64(0)
	for _, f := range p.Fields {
		if f.Tag != "KSUM" {
			continue
		}
		scopes, e := mapField(p.Fields, "KSUM")
		if e == nil && scopes.KeyKind == 1 && scopes.ValueKind == 0 && len(scopes.Pairs) == 0 {
			continue
		}
		if e != nil || scopes.KeyKind != 1 || scopes.ValueKind != 0 || len(scopes.Pairs) != 1 {
			return reject()
		}
		key, ok := scopes.Pairs[0].Key.([]byte)
		value, valid := scopes.Pairs[0].Value.(int64)
		if !ok || !valid || scope == "" || string(key) != scope {
			return reject()
		}
		scopeValue = value
	}
	ack, err := (Packet{Header: header}).Encode()
	if err != nil {
		return nil, err
	}
	notice := make([]byte, 12)
	binary.BigEndian.PutUint16(notice[2:4], 7)
	binary.BigEndian.PutUint16(notice[4:6], 50)
	notice[8] = 0x20
	resultKey := "No_Scope_Defined"
	if scope != "" {
		resultKey = fmt.Sprintf("%s=%d", scope, scopeValue)
	}
	update, err := (Packet{Header: notice, Fields: []Field{
		text("GRNM", string(name)), text("KEY", resultKey),
		{Tag: "LAST", Kind: 0, Value: int64(1)},
		{Tag: "STS", Kind: 3, Value: []Field{{Tag: "STAT", Kind: 4, Value: List{Kind: 3, Items: nil}}}},
		{Tag: "VID", Kind: 0, Value: vid},
	}}).Encode()
	return [][]byte{ack, update}, err
}
