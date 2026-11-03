package main

import (
	"fmt"
	"sort"
)

// FUN_006cc370 reads Stats extended-data id 5 via FUN_004bfdf0.
// FUN_00be8660 packs component 7 and id 5 into 0x00070005. A present,
// nonnegative value sets the profile's +0x41f readiness byte; absence leaves
// the doublesp startup action (FUN_0072d210) waiting forever. Zero means
// inactive, not unknown. Do not invent progression values for other ids.
const nfs13DoubleSPKey int64 = 7<<16 | 5

// The RPC acknowledgement alone does not remove the SDK's local game/player.
// Registry.leave only notifies other members; the departing client also needs
// NotifyPlayerRemoved, including the original title context and reason.
func nfs13PlayerRemovedNotification(raw []byte) ([]byte, error) {
	packet, err := decodePacket(raw)
	if err != nil {
		return nil, err
	}
	if packet.Component() != 4 || packet.Command() != 11 || packet.MessageType() != 0 {
		return nil, fmt.Errorf("not a remove-player request")
	}
	fields := make([]Field, 0, 4)
	for _, tag := range []string{"CNTX", "GID", "PID", "REAS"} {
		value, err := integerField(packet.Fields, tag)
		if err != nil {
			return nil, err
		}
		fields = append(fields, Field{Tag: tag, Kind: 0, Value: value})
	}
	return notification(40, fields)
}

func nfs13SessionDataReply(raw []byte) ([]byte, error) {
	component, command, kind, _ := blazeMetadata(raw)
	if component != 0x7802 || kind != 2 || (command != 1 && command != 2) {
		return raw, nil
	}
	packet, err := decodePacket(raw)
	if err != nil {
		return nil, err
	}
	data, err := structField(packet.Fields, "DATA")
	if err != nil {
		return nil, err
	}
	field, err := fieldAt(data, "DMAP", 5)
	if err != nil {
		return nil, err
	}
	values, ok := field.Value.(MapValue)
	if !ok || values.KeyKind != 0 || values.ValueKind != 0 {
		return nil, fmt.Errorf("NFS13 session DMAP is not an integer map")
	}
	for _, pair := range values.Pairs {
		key, ok := pair.Key.(int64)
		if !ok {
			return nil, fmt.Errorf("NFS13 session DMAP key is not an integer")
		}
		if key == nfs13DoubleSPKey {
			return raw, nil
		}
	}
	values.Pairs = append(values.Pairs, Pair{Key: nfs13DoubleSPKey, Value: int64(0)})
	sort.Slice(values.Pairs, func(i, j int) bool { return values.Pairs[i].Key.(int64) < values.Pairs[j].Key.(int64) })
	field.Value = values
	return packet.Encode()
}
