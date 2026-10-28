package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

const maxBlazeFrame = 16 << 20

const legacyZLOAuthToken = "WAHAHA_IMMA_ZLO_TOKEN"

//go:embed blaze_replay.json
var blazeReplayJSON []byte

// These are the ZCertMaker CA materials embedded in the recovered CLoader.
// CLoader installs/trusts this CA for its local TLS interception endpoints.
//
//go:embed zlo_tls_cert.pem
var zloTLSCertPEM []byte

//go:embed zlo_tls_key.pem
var zloTLSKeyPEM []byte

// This is the exact redirector identity selected by the recovered EA module
// for the legacy ZClient path.  Unlike the generated certificate above, the
// leaf is signed directly by the ZLO root and is sent without an intermediate.
// The PC DVD 1.0 DirtySSL client depends on that original chain shape.
//
//go:embed zlo_winter15_cert.pem
var zloWinter15CertPEM []byte

//go:embed zlo_winter15_key.pem
var zloWinter15KeyPEM []byte

type replayJSONEntry struct {
	Request string   `json:"request"`
	Replies []string `json:"replies"`
}

type replayEntry struct {
	request []byte
	replies [][]byte
}

type blazeServer struct {
	tlsConfig      *tls.Config
	corpus         []replayEntry
	registry       *registry
	advertiseHost  string
	nfs13          bool
	rewritePreAuth bool
	legacyEAID     string
	legacyAccount  int64
}

type blazeIdentity struct {
	name     string
	token    []byte
	id       int64
	gamePort int64
}

const (
	localGamePortBase  = int64(20000)
	localGamePortCount = int64(40000)
)

func gamePortForIdentity(id int64) int64 {
	return localGamePortBase + id%localGamePortCount
}

func gameVirtualAddressForPort(port int64) int64 {
	// 198.18.0.0/15 is reserved for benchmark/testing networks. Expose a
	// non-loopback address to Frostbite so it does not coalesce every local
	// peer into one loopback connection; the LSX shim translates it back to
	// the per-instance 127/8 transport address before calling Winsock.
	return int64(0xc6120000 | uint32(port))
}

func localBlazeIdentity(request []byte) (*blazeIdentity, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	auth, err := fieldAt(packet.Fields, "AUTH", 1)
	if err != nil {
		return nil, err
	}
	token, ok := auth.Value.([]byte)
	if !ok {
		return nil, errors.New("AUTH is not a string")
	}
	const prefix = "ZLOCAL1:"
	if !strings.HasPrefix(string(token), prefix) {
		return &blazeIdentity{name: "mxmstr", token: append([]byte(nil), token...), id: 2}, nil
	}
	name, err := hex.DecodeString(string(token[len(prefix):]))
	if err != nil || len(name) == 0 || len(name) > 64 || !utf8.Valid(name) {
		return nil, errors.New("invalid local identity token")
	}
	hash := fnv.New32a()
	_, _ = hash.Write(name)
	id := int64(hash.Sum32()&0x3fffffff) + 0x1000
	return &blazeIdentity{
		name: string(name), token: append([]byte(nil), token...), id: id,
		gamePort: gamePortForIdentity(id),
	}, nil
}

func (s *blazeServer) blazeIdentity(request []byte) (*blazeIdentity, error) {
	identity, err := localBlazeIdentity(request)
	if err != nil || !s.nfs13 || identity == nil ||
		string(identity.token) != legacyZLOAuthToken ||
		s.legacyEAID == "" || s.legacyAccount <= 0 {
		return identity, err
	}
	identity.name = s.legacyEAID
	identity.id = s.legacyAccount
	identity.gamePort = gamePortForIdentity(identity.id)
	return identity, nil
}

func rewriteIdentityFields(fields []Field, identity *blazeIdentity) {
	identityTags := map[string]bool{
		"AID": true, "BLID": true, "BUID": true, "CONG": true,
		"HPID": true, "HSES": true, "OGHI": true, "PID": true,
		"UID": true, "USID": true,
	}
	identityUUID := func(value []byte) []byte {
		// Preserve the captured UUID's role-specific prefix (game UUID versus
		// player UUID), but give every emulated identity a unique suffix.
		if len(value) != 36 || value[8] != '-' || value[13] != '-' ||
			value[18] != '-' || value[23] != '-' {
			return value
		}
		result := append([]byte(nil), value...)
		copy(result[28:], fmt.Sprintf("%08X", uint32(identity.id)))
		return result
	}
	var rewriteValue func(byte, any) any
	rewriteValue = func(kind byte, value any) any {
		switch kind {
		case 3:
			if nested, ok := value.([]Field); ok {
				rewriteIdentityFields(nested, identity)
				return nested
			}
		case 4:
			if list, ok := value.(List); ok {
				for index, item := range list.Items {
					switch typed := item.(type) {
					case []Field:
						rewriteIdentityFields(typed, identity)
						list.Items[index] = typed
					case LegacyAddress:
						rewriteIdentityFields(typed.Fields, identity)
						list.Items[index] = typed
					}
				}
				return list
			}
		case 5:
			if mapped, ok := value.(MapValue); ok {
				for index := range mapped.Pairs {
					mapped.Pairs[index].Key = rewriteValue(mapped.KeyKind, mapped.Pairs[index].Key)
					mapped.Pairs[index].Value = rewriteValue(mapped.ValueKind, mapped.Pairs[index].Value)
				}
				return mapped
			}
		case 6:
			if union, ok := value.(Union); ok && union.Field != nil {
				union.Field.Value = rewriteValue(union.Field.Kind, union.Field.Value)
				return union
			}
		case 7:
			if variable, ok := value.(Variable); ok && variable.Field != nil {
				variable.Field.Value = rewriteValue(variable.Field.Kind, variable.Field.Value)
				return variable
			}
		}
		return value
	}
	for index := range fields {
		field := &fields[index]
		if field.Kind == 0 && identityTags[field.Tag] {
			if value, ok := field.Value.(int64); ok && (value == 2 || value == 2435729) {
				field.Value = identity.id
			}
		}
		if field.Kind == 1 && field.Tag == "UUID" {
			if value, ok := field.Value.([]byte); ok {
				field.Value = identityUUID(value)
			}
		}
		if field.Kind == 4 && field.Tag == "ADMN" {
			if list, ok := field.Value.(List); ok && list.Kind == 0 {
				for itemIndex, item := range list.Items {
					if value, itemOK := item.(int64); itemOK && (value == 2 || value == 2435729) {
						list.Items[itemIndex] = identity.id
					}
				}
				field.Value = list
			}
		}
		if field.Kind == 9 && (field.Tag == "BOID" || field.Tag == "UGID") {
			if objectID, ok := field.Value.(ObjectID); ok && len(objectID) != 0 &&
				(objectID[len(objectID)-1] == 2 || objectID[len(objectID)-1] == 2435729) {
				objectID[len(objectID)-1] = identity.id
				field.Value = objectID
			}
		}
		if field.Kind == 1 {
			if value, ok := field.Value.([]byte); ok {
				switch string(value) {
				case "mxmstr":
					field.Value = []byte(identity.name)
				case "offline@lan":
					field.Value = []byte(identity.name + "@lan")
				case "WAHAHA_IMMA_ZLO_TOKEN":
					field.Value = append([]byte(nil), identity.token...)
				}
			}
		}
		field.Value = rewriteValue(field.Kind, field.Value)
	}
}

func personalizeReplayReply(frame []byte, now int64, identity *blazeIdentity) ([]byte, int, error) {
	reply, refreshed, err := prepareReplayReply(frame, now)
	if err != nil || identity == nil {
		return reply, refreshed, err
	}
	packet, err := decodePacket(reply)
	if err != nil {
		return nil, refreshed, err
	}
	rewriteIdentityFields(packet.Fields, identity)
	reply, err = packet.Encode()
	return reply, refreshed, err
}

const nfs13PlateScope = "license_plate"

func setNFS13PlateScope(fields []Field) []Field {
	scope := Field{
		Tag:  "KSUM",
		Kind: 5,
		Value: MapValue{
			KeyKind:   1,
			ValueKind: 0,
			Pairs: []Pair{{
				Key:   []byte(nfs13PlateScope),
				Value: int64(0),
			}},
		},
	}
	for i := range fields {
		if fields[i].Tag == scope.Tag {
			fields[i] = scope
			return fields
		}
		if fields[i].Tag > scope.Tag {
			fields = append(fields, Field{})
			copy(fields[i+1:], fields[i:])
			fields[i] = scope
			return fields
		}
	}
	return append(fields, scope)
}

func nfs13RequestedScopeKey(fields []Field) ([]byte, error) {
	scopes, err := mapField(fields, "KSUM")
	if err != nil {
		// The PC DVD 1.0 client does not echo the descriptor's KSUM map in its
		// getStatsByGroup request.  It still expects the asynchronous result key
		// to be parseable as "scope=value"; using the descriptor's sole advertised
		// scope is therefore the deterministic equivalent of the omitted map.
		// Only apply this default when KSUM is absent.  A present but malformed map
		// remains a protocol error instead of being silently reinterpreted.
		for _, field := range fields {
			if field.Tag == "KSUM" {
				return nil, fmt.Errorf("NFS13 stats request has an invalid advertised key scope: %w", err)
			}
		}
		return []byte(nfs13PlateScope + "=0"), nil
	}
	if scopes.KeyKind != 1 || scopes.ValueKind != 0 || len(scopes.Pairs) != 1 {
		return nil, errors.New("NFS13 stats request has an invalid key-scope map")
	}
	name, ok := scopes.Pairs[0].Key.([]byte)
	if !ok || string(name) != nfs13PlateScope {
		return nil, errors.New("NFS13 stats request has an unexpected key scope")
	}
	value, ok := scopes.Pairs[0].Value.(int64)
	if !ok {
		return nil, errors.New("NFS13 stats request has an invalid key-scope value")
	}
	return []byte(fmt.Sprintf("%s=%d", name, value)), nil
}

func nfs13StatsReply(request, reply []byte) ([]byte, error) {
	requestPacket, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	group, err := bytesField(requestPacket.Fields, "NAME")
	if err != nil {
		return nil, err
	}
	replyPacket, err := decodePacket(reply)
	if err != nil {
		return nil, err
	}
	replyComponent, replyCommand, replyType, _ := blazeMetadata(reply)
	if replyComponent != 7 {
		return append([]byte(nil), reply...), nil
	}
	switch {
	case requestPacket.Command() == 4 && replyCommand == 4 && replyType == 1:
		// The replay corpus was captured from NFS14. NFS13 asks for its own
		// license_plate groups, so returning the captured MetaData/PlayerStats
		// descriptor makes the subsequent getStatsByGroup request use the wrong
		// schema. Preserve the non-empty descriptor scaffolding, which NFS13
		// dereferences unconditionally, but bind the envelope to the requested
		// group.
		for _, tag := range []string{"CNAM", "DESC", "NAME"} {
			field, fieldErr := fieldAt(replyPacket.Fields, tag, 1)
			if fieldErr != nil {
				return nil, fieldErr
			}
			field.Value = append([]byte(nil), group...)
		}
		// NFS13's license-plate completion handler requires both an async result
		// whose key matches the request and a parseable "scope=value" key. The
		// captured NFS14 descriptor is unscoped, which makes those requirements
		// mutually exclusive: No_Scope_Defined attaches but crashes in atoi,
		// while No_Scope_Defined=0 is parseable but does not attach. Advertise the
		// scope that NFS13 itself uses so the SDK includes it in command 16.
		replyPacket.Fields = setNFS13PlateScope(replyPacket.Fields)
	case requestPacket.Command() == 16 && replyCommand == 50 && replyType == 2:
		// The captured NFS14 result row also describes a different group schema.
		// Return an empty, well-formed result set: NFS13's consumer explicitly
		// checks begin == end before it iterates rows, so this supplies the required
		// result object without feeding foreign values into the plate parser.
		groupField, fieldErr := fieldAt(replyPacket.Fields, "GRNM", 1)
		if fieldErr != nil {
			return nil, fieldErr
		}
		groupField.Value = append([]byte(nil), group...)
		key, fieldErr := fieldAt(replyPacket.Fields, "KEY", 1)
		if fieldErr != nil {
			return nil, fieldErr
		}
		key.Value, fieldErr = nfs13RequestedScopeKey(requestPacket.Fields)
		if fieldErr != nil {
			return nil, fieldErr
		}
		status, fieldErr := structField(replyPacket.Fields, "STS")
		if fieldErr != nil {
			return nil, fieldErr
		}
		statsField, fieldErr := fieldAt(status, "STAT", 4)
		if fieldErr != nil {
			return nil, fieldErr
		}
		stats, ok := statsField.Value.(List)
		if !ok || stats.Kind != 3 {
			return nil, errors.New("Stats update has an invalid result list")
		}
		stats.Items = nil
		statsField.Value = stats
	default:
		return append([]byte(nil), reply...), nil
	}
	return replyPacket.Encode()
}

func rewriteByteStrings(fields []Field, replacements map[string][]byte) {
	var rewriteValue func(byte, any) any
	rewriteValue = func(kind byte, value any) any {
		switch kind {
		case 1, 2:
			if raw, ok := value.([]byte); ok {
				if replacement, found := replacements[string(raw)]; found {
					return append([]byte(nil), replacement...)
				}
			}
		case 3:
			switch nested := value.(type) {
			case []Field:
				rewriteByteStrings(nested, replacements)
				return nested
			case LegacyAddress:
				rewriteByteStrings(nested.Fields, replacements)
				return nested
			}
		case 4:
			if list, ok := value.(List); ok {
				for index, item := range list.Items {
					list.Items[index] = rewriteValue(list.Kind, item)
				}
				return list
			}
		case 5:
			if mapped, ok := value.(MapValue); ok {
				for index := range mapped.Pairs {
					mapped.Pairs[index].Key = rewriteValue(mapped.KeyKind, mapped.Pairs[index].Key)
					mapped.Pairs[index].Value = rewriteValue(mapped.ValueKind, mapped.Pairs[index].Value)
				}
				return mapped
			}
		case 6:
			if union, ok := value.(Union); ok && union.Field != nil {
				union.Field.Value = rewriteValue(union.Field.Kind, union.Field.Value)
				return union
			}
		case 7:
			if variable, ok := value.(Variable); ok && variable.Field != nil {
				variable.Field.Value = rewriteValue(variable.Field.Kind, variable.Field.Value)
				return variable
			}
		}
		return value
	}
	for index := range fields {
		fields[index].Value = rewriteValue(fields[index].Kind, fields[index].Value)
	}
}

func extendNFS13PreAuthConfig(fields []Field, baseURL string) bool {
	for index := range fields {
		field := &fields[index]
		if field.Kind == 5 {
			mapped, ok := field.Value.(MapValue)
			if !ok || mapped.KeyKind != 1 || mapped.ValueKind != 1 {
				continue
			}
			isClientConfig := false
			for _, pair := range mapped.Pairs {
				key, keyOK := pair.Key.([]byte)
				if keyOK && string(key) == "blazeServerClientId" {
					isClientConfig = true
					break
				}
			}
			if !isClientConfig {
				continue
			}
			values := []struct{ key, value string }{
				{"autolog_host", baseURL},
				{"autolog_host_secure", baseURL},
				{"server_manifest", "nfs13/server-manifest"},
				{"server_manifest_secure", "nfs13/server-manifest"},
				{"layout_bundles", "nfs13/layout-bundles"},
				{"layout_bundles_secure", "nfs13/layout-bundles"},
				{"lua_bundles", "nfs13/lua-bundles"},
				{"lua_bundles_secure", "nfs13/lua-bundles"},
			}
			for _, setting := range values {
				replaced := false
				for pairIndex := range mapped.Pairs {
					key, keyOK := mapped.Pairs[pairIndex].Key.([]byte)
					if keyOK && string(key) == setting.key {
						mapped.Pairs[pairIndex].Value = []byte(setting.value)
						replaced = true
						break
					}
				}
				if !replaced {
					mapped.Pairs = append(mapped.Pairs, Pair{
						Key: []byte(setting.key), Value: []byte(setting.value),
					})
				}
			}
			field.Value = mapped
			return true
		}
		if field.Kind == 3 {
			nested, ok := field.Value.([]Field)
			if ok && extendNFS13PreAuthConfig(nested, baseURL) {
				field.Value = nested
				return true
			}
		}
	}
	return false
}

func nfs13PreAuthReply(request, reply []byte, advertiseHost string) ([]byte, error) {
	requestPacket, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	clientData, err := structField(requestPacket.Fields, "CDAT")
	if err != nil {
		return nil, err
	}
	serviceField, err := fieldAt(clientData, "SVCN", 1)
	if err != nil {
		return nil, err
	}
	serviceName, ok := serviceField.Value.([]byte)
	if !ok || len(serviceName) == 0 {
		return nil, errors.New("SVCN is not a non-empty string")
	}
	replyComponent, replyCommand, replyType, _ := blazeMetadata(reply)
	if replyComponent != 9 || replyCommand != 7 || replyType != 1 {
		return nil, errors.New("unexpected pre-auth reply metadata")
	}
	replyPacket, err := decodePacket(reply)
	if err != nil {
		return nil, err
	}
	rewriteByteStrings(replyPacket.Fields, map[string][]byte{
		"nfs-rivals-pc":          serviceName,
		"NFS14-Rivals-PC-Server": []byte("NFS13-PC-Server"),
	})
	baseURL := nfs13AutologBaseURL(advertiseHost)
	if !extendNFS13PreAuthConfig(replyPacket.Fields, baseURL) {
		return nil, errors.New("pre-auth reply lacks the client configuration map")
	}
	return replyPacket.Encode()
}

func personalizeNFS13UserSessionNotification(frame []byte, identity *blazeIdentity) ([]byte, error) {
	if identity == nil {
		return frame, nil
	}
	component, command, messageType, _ := blazeMetadata(frame)
	if component != 0x7802 || (command != 2 && command != 5) || messageType != 2 {
		return frame, nil
	}
	packet, err := decodePacket(frame)
	if err != nil {
		return nil, err
	}
	rewriteInteger := func(fields []Field, tag string) error {
		field, fieldErr := fieldAt(fields, tag, 0)
		if fieldErr != nil {
			return fieldErr
		}
		value, ok := field.Value.(int64)
		if !ok {
			return fmt.Errorf("UserSessions %s is not an integer", tag)
		}
		if value == 2 || value == 2435729 {
			field.Value = identity.id
		}
		return nil
	}
	if command == 5 {
		if err := rewriteInteger(packet.Fields, "ID"); err != nil {
			return nil, fmt.Errorf("UserSessions command 5 identity field: %w", err)
		}
	} else {
		user, err := structField(packet.Fields, "USER")
		if err != nil {
			return nil, err
		}
		for _, tag := range []string{"ID", "ORIG"} {
			if err := rewriteInteger(user, tag); err != nil {
				return nil, fmt.Errorf("UserSessions command 2 %s field: %w", tag, err)
			}
		}
		data, err := structField(packet.Fields, "DATA")
		if err != nil {
			return nil, err
		}
		userListField, err := fieldAt(data, "ULST", 4)
		if err != nil {
			return nil, err
		}
		userList, ok := userListField.Value.(List)
		if !ok || userList.Kind != 9 {
			return nil, errors.New("UserSessions ULST is not an object-ID list")
		}
		for index, item := range userList.Items {
			objectID, ok := item.(ObjectID)
			if !ok || len(objectID) == 0 {
				return nil, errors.New("UserSessions ULST contains an invalid object ID")
			}
			last := len(objectID) - 1
			if objectID[last] == 2 || objectID[last] == 2435729 {
				objectID[last] = identity.id
			}
			userList.Items[index] = objectID
		}
		userListField.Value = userList
	}
	return packet.Encode()
}

// The successful ZClient login sends three private UserSessions frames around
// the correlated Authentication/login reply.  The original replay generator
// incorrectly rejected their 0x7802 component as out of range, leaving only
// the standard 1/152 response in blaze_replay.json.  Keep the captured order:
// extended-data notification, login reply, user-added notification, then the
// final session notification.
var authenticationSessionFrames = []string{
	"00707802000800002040000086cbe30093d5f2d60c8b5a6400028e7a640982e0030202933bad01076d786d73747200ae5e4001165741484148415f494d4d415f5a4c4f5f544f4b454e00b21cf40094fecbab0db2cbe70094fecbab0db61a6c010c6f66666c696e65406c616e00c299000002c2c8740004d699000002",
	"004978020002000020000000921d210392d8700500000201b407818090800f00d6ccf404090182e003020200d7397203869900000286cbe30093d5f2d60ca640000002ba1b6501076d786d73747200bf2a67000200",
	"000a780200050000200000009ac9f30003a640000002",
}

// EA.dll treats UserSessions command 35 as a short-lived probe. It returns an
// error-type frame containing ERRC=0, then closes the connection. These probes
// use their own TLS connections and are not present in the main ColdCli replay
// stream, so handle them independently of the ordered corpus cursor.
var userSessionsProbeError = []byte{
	0x00, 0x05, 0x78, 0x02, 0x00, 0x23, 0x00, 0x00,
	0x30, 0x00, 0x00, 0x00, 0x97, 0x2c, 0xa3, 0x00, 0x00,
}

func userSessionsProbeReply(correlation uint32) []byte {
	reply := append([]byte(nil), userSessionsProbeError...)
	setBlazeCorrelation(reply, correlation)
	return reply
}

func softwareProductReply(request []byte) ([]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	softwareIDsField, err := fieldAt(packet.Fields, "SWIS", 4)
	if err != nil {
		return nil, err
	}
	softwareIDs, ok := softwareIDsField.Value.(List)
	if !ok || softwareIDs.Kind != 0 {
		return nil, errors.New("SWIS is not an integer list")
	}
	items := make([]any, 0, len(softwareIDs.Items))
	for _, item := range softwareIDs.Items {
		softwareID, ok := item.(int64)
		if !ok {
			return nil, errors.New("SWIS contains a non-integer value")
		}
		items = append(items, []Field{{Tag: "SWID", Kind: 0, Value: softwareID}})
	}
	header := append([]byte(nil), packet.Header...)
	header[6], header[7] = 0, 0
	header[8] = header[8]&0x0f | 0x10
	reply := Packet{
		Header: header,
		Fields: []Field{{Tag: "SPWA", Kind: 4, Value: List{Kind: 3, Items: items}}},
	}
	return reply.Encode()
}

func emptySuccessReply(request []byte) ([]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	header := append([]byte(nil), packet.Header...)
	header[6], header[7] = 0, 0
	header[8] = header[8]&0x0f | 0x10
	return (Packet{Header: header}).Encode()
}

func destroyGameReply(request []byte) ([]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	if packet.Component() != 4 || packet.Command() != 2 || packet.MessageType() != 0 {
		return nil, errors.New("not a GameManager destroy-game request")
	}
	gameID, err := integerField(packet.Fields, "GID")
	if err != nil || gameID <= 0 {
		return nil, errors.New("destroy-game request has no game ID")
	}
	if _, err = integerField(packet.Fields, "REAS"); err != nil {
		return nil, errors.New("destroy-game request has no destruction reason")
	}
	header := append([]byte(nil), packet.Header...)
	header[6], header[7] = 0, 0
	header[8] = header[8]&0x0f | 0x10
	return (Packet{
		Header: header,
		Fields: []Field{{Tag: "GID", Kind: 0, Value: gameID}},
	}).Encode()
}

func utilPingReply(request []byte, now int64) ([]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	if packet.Component() != 9 || packet.Command() != 2 || packet.MessageType() != 0 {
		return nil, errors.New("not a Utility ping request")
	}
	header := append([]byte(nil), packet.Header...)
	header[6], header[7] = 0, 0
	header[8] = header[8]&0x0f | 0x10
	return (Packet{
		Header: header,
		Fields: []Field{{Tag: "STIM", Kind: 0, Value: now}},
	}).Encode()
}

func utilClientConfigReply(request []byte, nfs13AutologURL string) ([]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	if packet.Component() != 9 || packet.Command() != 1 || packet.MessageType() != 0 {
		return nil, errors.New("not a Utility fetchClientConfig request")
	}
	keyField, err := fieldAt(packet.Fields, "CFID", 1)
	if err != nil {
		return nil, err
	}
	key, ok := keyField.Value.([]byte)
	if !ok {
		return nil, errors.New("CFID is not a string")
	}

	header := append([]byte(nil), packet.Header...)
	header[6], header[7] = 0, 0
	header[8] = header[8]&0x0f | 0x10
	reply := Packet{Header: header}
	if string(key) == "Url" && nfs13AutologURL != "" {
		// These values belong to NFS13's Url client-config bucket.  Adding
		// them to the SDK PreAuth CONF map leaves the game's URL manager
		// empty; its server-manifest builder then produces only "/" and
		// terminates before opening an HTTP socket.
		reply.Fields = []Field{{
			Tag: "CONF", Kind: 5,
			Value: MapValue{KeyKind: 1, ValueKind: 1, Pairs: []Pair{
				{Key: []byte("autolog_host"), Value: []byte(nfs13AutologURL)},
				{Key: []byte("autolog_host_secure"), Value: []byte(nfs13AutologURL)},
				{Key: []byte("server_manifest"), Value: []byte("nfs13/server-manifest")},
				{Key: []byte("server_manifest_secure"), Value: []byte("nfs13/server-manifest")},
				{Key: []byte("layout_bundles"), Value: []byte("nfs13/layout-bundles")},
				{Key: []byte("layout_bundles_secure"), Value: []byte("nfs13/layout-bundles")},
				{Key: []byte("lua_bundles"), Value: []byte("nfs13/lua-bundles")},
				{Key: []byte("lua_bundles_secure"), Value: []byte("nfs13/lua-bundles")},
			}},
		}}
	} else if string(key) == "Game" {
		// NFS13's online bootstrap asks for its game-side tweakables after login.
		// An empty response leaves the SDK's real-time-presence watchdog at its
		// compiled 120-second default even though this offline backend does not
		// implement the presence stream.  The Blaze transport remains healthy,
		// then Autolog deliberately tears it down when that watchdog expires.
		// Keep real-time presence enabled because NFS13 also uses this flag as its
		// local Autolog-availability gate.  Extending the watchdog and disabling
		// friend-position updates avoids the unsupported stream without making the
		// pause-menu reconnect fail before it can issue a Blaze RPC.
		reply.Fields = []Field{{
			Tag: "CONF", Kind: 5,
			Value: MapValue{KeyKind: 1, ValueKind: 1, Pairs: []Pair{
				{Key: []byte("realtime_presence_active"), Value: []byte("1")},
				{Key: []byte("realtime_presence_client_timeout_seconds"), Value: []byte("86400")},
				{Key: []byte("request_friend_presence_updates_enabled"), Value: []byte("0")},
			}},
		}}
	}
	return reply.Encode()
}

func advanceGameStateReplies(request []byte) ([][]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	if packet.Component() != 4 || packet.Command() != 3 || packet.MessageType() != 0 {
		return nil, errors.New("not a GameManager advance-state request")
	}
	if _, err = integerField(packet.Fields, "GID"); err != nil {
		return nil, err
	}
	if _, err = integerField(packet.Fields, "GSTA"); err != nil {
		return nil, err
	}

	reply, err := emptySuccessReply(request)
	if err != nil {
		return nil, err
	}
	// NotifyGameStateChange mirrors the live GID/GSTA pair instead of replaying
	// one of the two states present in the finite capture. Nucleus' isolated
	// profile can cause Rivals to emit additional valid transitions.
	packet.Header[4], packet.Header[5] = 0, 100
	packet.Header[6], packet.Header[7] = 0, 0
	packet.Header[8] = packet.Header[8]&0x0f | 0x20
	notification, err := packet.Encode()
	if err != nil {
		return nil, err
	}
	setBlazeCorrelation(notification, 0)
	return [][]byte{reply, notification}, nil
}

func setGameSettingsReplies(request []byte) ([][]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	if packet.Component() != 4 || packet.Command() != 4 || packet.MessageType() != 0 {
		return nil, errors.New("not a GameManager set-game-settings request")
	}
	gameID, err := integerField(packet.Fields, "GID")
	if err != nil {
		return nil, err
	}
	settings, err := integerField(packet.Fields, "GSET")
	if err != nil {
		return nil, err
	}

	reply, err := emptySuccessReply(request)
	if err != nil {
		return nil, err
	}
	// Blaze acknowledges setGameSettings with EmptyMessage and publishes the
	// authoritative value through NotifyGameSettingsChange (command 0x6e). The
	// notification schema names the settings field ATTR rather than the request's
	// GSET, so construct its body explicitly instead of reusing the request body.
	packet.Header[4], packet.Header[5] = 0, 0x6e
	packet.Header[6], packet.Header[7] = 0, 0
	packet.Header[8] = packet.Header[8]&0x0f | 0x20
	packet.Fields = []Field{
		{Tag: "ATTR", Kind: 0, Value: settings},
		{Tag: "GID", Kind: 0, Value: gameID},
	}
	notification, err := packet.Encode()
	if err != nil {
		return nil, err
	}
	setBlazeCorrelation(notification, 0)
	return [][]byte{reply, notification}, nil
}

// nfs13MatchmakingSetup carries the title's live lobby attributes into the
// captured setup template and reports whether the request is create-only.
// NFS13 uses startMatchmaking for both public search and "Create friends
// game": MODE=3 is find-or-create, while MODE=2 is create-only.
func nfs13MatchmakingSetup(request, setup []byte) ([]byte, bool, error) {
	requestPacket, err := decodePacket(request)
	if err != nil {
		return nil, false, err
	}
	if requestPacket.Component() != 4 || requestPacket.Command() != 13 || requestPacket.MessageType() != 0 {
		return nil, false, errors.New("not a GameManager start-matchmaking request")
	}
	mode, err := integerField(requestPacket.Fields, "MODE")
	if err != nil {
		return nil, false, err
	}
	if mode&3 == 0 {
		return nil, false, fmt.Errorf("unsupported matchmaking mode %d", mode)
	}
	createOnly := mode&2 != 0 && mode&1 == 0
	requestAttributes, err := mapField(requestPacket.Fields, "ATTR")
	if err != nil || requestAttributes.KeyKind != 1 || requestAttributes.ValueKind != 1 {
		return nil, false, errors.New("invalid matchmaking attributes")
	}

	setupPacket, err := decodePacket(setup)
	if err != nil {
		return nil, false, err
	}
	if setupPacket.Component() != 4 || setupPacket.Command() != 20 || setupPacket.MessageType() != 2 {
		return nil, false, errors.New("not a GameManager setup notification")
	}
	gameFields, err := structField(setupPacket.Fields, "GAME")
	if err != nil {
		return nil, false, err
	}
	setupAttributes, err := mapField(gameFields, "ATTR")
	if err != nil || setupAttributes.KeyKind != 1 || setupAttributes.ValueKind != 1 {
		return nil, false, errors.New("invalid setup attributes")
	}
	merged := make([]Pair, 0, len(setupAttributes.Pairs)+len(requestAttributes.Pairs))
	for _, pair := range setupAttributes.Pairs {
		merged = append(merged, Pair{
			Key:   append([]byte(nil), pair.Key.([]byte)...),
			Value: append([]byte(nil), pair.Value.([]byte)...),
		})
	}
	for _, live := range requestAttributes.Pairs {
		key := live.Key.([]byte)
		replaced := false
		for index := range merged {
			if bytes.Equal(merged[index].Key.([]byte), key) {
				merged[index].Value = append([]byte(nil), live.Value.([]byte)...)
				replaced = true
				break
			}
		}
		if !replaced {
			merged = append(merged, Pair{
				Key:   append([]byte(nil), key...),
				Value: append([]byte(nil), live.Value.([]byte)...),
			})
		}
	}
	attributeField, err := fieldAt(gameFields, "ATTR", 5)
	if err != nil {
		return nil, false, err
	}
	attributeField.Value = MapValue{KeyKind: 1, ValueKind: 1, Pairs: merged}
	result, err := setupPacket.Encode()
	return result, createOnly, err
}

// nfs13ResetDedicatedServerSetup turns the captured matchmaking setup into the
// setup notification for GameManager/resetDedicatedServer. NFS13 uses that RPC
// for "Create friends game": the request is a CreateGameRequest and the RPC
// response itself is empty; the created game arrives asynchronously through
// NotifyGameSetup.
func nfs13ResetDedicatedServerSetup(request, setup []byte) ([]byte, error) {
	requestPacket, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	if requestPacket.Component() != 4 || requestPacket.Command() != 25 || requestPacket.MessageType() != 0 {
		return nil, errors.New("not a GameManager reset-dedicated-server request")
	}
	requestAttributes, err := mapField(requestPacket.Fields, "ATTR")
	if err != nil || requestAttributes.KeyKind != 1 || requestAttributes.ValueKind != 1 {
		return nil, errors.New("invalid reset-dedicated-server attributes")
	}

	setupPacket, err := decodePacket(setup)
	if err != nil {
		return nil, err
	}
	if setupPacket.Component() != 4 || setupPacket.Command() != 20 || setupPacket.MessageType() != 2 {
		return nil, errors.New("not a GameManager setup notification")
	}
	gameFields, err := structField(setupPacket.Fields, "GAME")
	if err != nil {
		return nil, err
	}
	setupAttributes, err := mapField(gameFields, "ATTR")
	if err != nil || setupAttributes.KeyKind != 1 || setupAttributes.ValueKind != 1 {
		return nil, errors.New("invalid setup attributes")
	}
	// Preserve the exact replicated-game contract already accepted by NFS13's
	// public matchmaking path. The reset request contains client preferences,
	// not authoritative replicated values: echoing its capacity, topology,
	// settings, version, attributes, and team index produced a setup the title
	// consistently abandoned. The only server-owned difference needed for this
	// path is private membership.
	attributeField, err := fieldAt(gameFields, "ATTR", 5)
	if err != nil {
		return nil, err
	}
	attributeField.Value = MapValue{KeyKind: 1, ValueKind: 1, Pairs: []Pair{{
		Key:   []byte("gameMembershipRequirements"),
		Value: []byte("FriendsOnly"),
	}}}

	// GNAM and PSAS are materialized by Blaze rather than blindly echoed from
	// CreateGameRequest. NFS13 leaves GNAM/GCTR empty, while every accepted
	// setup carries the host persona as GNAM and a selected ping-site alias.
	// Erasing the template's "zlo" PSAS made the otherwise valid local setup
	// look like an unassigned dedicated-server result.
	gameName, err := bytesField(requestPacket.Fields, "GNAM")
	if err != nil {
		return nil, err
	}
	if len(gameName) == 0 {
		roster, rosterErr := listField(setupPacket.Fields, "PROS")
		if rosterErr != nil || roster.Kind != 3 || len(roster.Items) == 0 {
			return nil, errors.New("reset-dedicated-server setup has no host player")
		}
		hostPlayer, playerErr := fieldsFromItem(roster.Items[0])
		if playerErr != nil {
			return nil, playerErr
		}
		gameName, playerErr = bytesField(hostPlayer, "NAME")
		if playerErr != nil || len(gameName) == 0 {
			return nil, errors.New("reset-dedicated-server setup has no host name")
		}
	}
	gameNameField, err := fieldAt(gameFields, "GNAM", 1)
	if err != nil {
		return nil, err
	}
	gameNameField.Value = append([]byte(nil), gameName...)

	// MatchmakingSetupContext cannot be reused here: no client-side matchmaking
	// job exists for cmd25, so NFS13 treats that notification as an unsolicited
	// host injection and immediately destroys it. Route the otherwise proven
	// setup through the reset-dedicated-server job that initiated this request.
	reasonValue := Field{Tag: "VALU", Kind: 3, Value: []Field{
		{Tag: "ERR", Kind: 0, Value: int64(0)},
	}}
	reasonField, err := fieldAt(setupPacket.Fields, "REAS", 6)
	if err != nil {
		return nil, err
	}
	reasonField.Value = Union{Index: 1, Field: &reasonValue}
	return setupPacket.Encode()
}

func associationUpdateReply(request []byte) ([]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	packet.Header[6], packet.Header[7] = 0, 0
	packet.Header[8] = packet.Header[8]&0x0f | 0x10
	// AssociationLists.UpdateListMembersResponse. No server-side social
	// roster is maintained yet, so acknowledge the mutation with both result
	// vectors present and empty instead of dropping the Blaze connection.
	packet.Fields = []Field{
		{Tag: "LMID", Kind: 4, Value: List{Kind: 3, Items: []any{}}},
		{Tag: "REM", Kind: 4, Value: List{Kind: 3, Items: []any{}}},
	}
	return packet.Encode()
}

func nfs13AssociationListsReply(request []byte, identity *blazeIdentity) ([]byte, error) {
	if identity == nil || identity.id <= 0 {
		return nil, errors.New("NFS13 Association Lists request has no authenticated identity")
	}
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	requested, err := listField(packet.Fields, "ALST")
	if err != nil || requested.Kind != 3 || len(requested.Items) != 1 {
		return nil, errors.New("NFS13 Association Lists request does not contain one list descriptor")
	}
	requestedInfo, err := fieldsFromItem(requested.Items[0])
	if err != nil {
		return nil, err
	}
	requestedID, err := structField(requestedInfo, "LID")
	if err != nil {
		return nil, err
	}
	listType, err := integerField(requestedID, "TYPE")
	if err != nil || listType != 1 {
		return nil, errors.New("NFS13 Association Lists request is not for the friend list")
	}
	requestedFlags, err := integerField(requestedInfo, "FLGS")
	if err != nil || requestedFlags&1 == 0 {
		return nil, errors.New("NFS13 Association Lists request did not request a subscription")
	}

	packet.Header[6], packet.Header[7] = 0, 0
	packet.Header[8] = packet.Header[8]&0x0f | 0x10
	packet.Fields = []Field{{
		Tag: "LMAP", Kind: 4,
		Value: List{Kind: 3, Items: []any{[]Field{
			{Tag: "INFO", Kind: 3, Value: []Field{
				{Tag: "BOID", Kind: 9, Value: ObjectID{25, listType, identity.id}},
				{Tag: "FLGS", Kind: 0, Value: int64(1)},
				{Tag: "LID", Kind: 3, Value: []Field{
					{Tag: "LNM", Kind: 1, Value: []byte("friendList")},
					{Tag: "TYPE", Kind: 0, Value: listType},
				}},
				{Tag: "LMS", Kind: 0, Value: int64(100)},
				{Tag: "PRID", Kind: 0, Value: int64(0)},
			}},
			{Tag: "MEML", Kind: 4, Value: List{Kind: 3, Items: []any{}}},
			{Tag: "OFRC", Kind: 0, Value: int64(0)},
			{Tag: "TOCT", Kind: 0, Value: int64(0)},
		}}},
	}}
	return packet.Encode()
}

func nfs13PlaygroupState(identity *blazeIdentity, address *Union) ([]Field, error) {
	if identity == nil || identity.id <= 0 {
		return nil, errors.New("NFS13 playgroup has no authenticated identity")
	}
	if address == nil || address.Index != 2 || address.Field == nil || address.Field.Kind != 3 {
		return nil, errors.New("NFS13 playgroup has no network address")
	}

	const (
		playgroupID      = int64(1)
		allPermissions   = int64(31)
		fullMeshTopology = int64(130)
		privatePresence  = int64(2)
		maxGroupMembers  = int64(8)
	)
	emptyStringMap := func() MapValue {
		return MapValue{KeyKind: 1, ValueKind: 1, Pairs: []Pair{}}
	}
	user := []Field{
		{Tag: "AID", Kind: 0, Value: identity.id},
		{Tag: "ALOC", Kind: 0, Value: int64(0)},
		{Tag: "EXBB", Kind: 2, Value: []byte{}},
		{Tag: "EXID", Kind: 0, Value: identity.id},
		{Tag: "ID", Kind: 0, Value: identity.id},
		{Tag: "NAME", Kind: 1, Value: []byte(identity.name)},
	}
	member := []Field{
		{Tag: "ATTR", Kind: 5, Value: emptyStringMap()},
		{Tag: "JTIM", Kind: 0, Value: time.Now().Unix()},
		{Tag: "PERM", Kind: 0, Value: allPermissions},
		{Tag: "PNET", Kind: 6, Value: *address},
		{Tag: "SID", Kind: 0, Value: int64(0)},
		{Tag: "USER", Kind: 3, Value: user},
	}
	info := []Field{
		{Tag: "ATTR", Kind: 5, Value: emptyStringMap()},
		{Tag: "ENBV", Kind: 0, Value: int64(0)},
		{Tag: "HNET", Kind: 6, Value: *address},
		{Tag: "HSID", Kind: 0, Value: int64(0)},
		{Tag: "JOIN", Kind: 0, Value: int64(0)},
		{Tag: "MLIM", Kind: 0, Value: maxGroupMembers},
		{Tag: "NAME", Kind: 1, Value: []byte(identity.name + "'s group")},
		{Tag: "NTOP", Kind: 0, Value: fullMeshTopology},
		{Tag: "OWNR", Kind: 0, Value: identity.id},
		{Tag: "PGID", Kind: 0, Value: playgroupID},
		{Tag: "PRES", Kind: 0, Value: privatePresence},
		{Tag: "UKEY", Kind: 1, Value: []byte(fmt.Sprintf("nfs13-lan-%d", identity.id))},
		{Tag: "UPRS", Kind: 0, Value: int64(1)},
		{Tag: "UUID", Kind: 1, Value: []byte(fmt.Sprintf("00000000-0000-0000-0000-%012d", identity.id))},
		{Tag: "VOIP", Kind: 0, Value: int64(0)},
		{Tag: "XNNC", Kind: 2, Value: []byte{}},
		{Tag: "XSES", Kind: 2, Value: []byte{}},
	}

	return []Field{
		{Tag: "INFO", Kind: 3, Value: info},
		{Tag: "MLST", Kind: 4, Value: List{Kind: 3, Items: []any{member}}},
	}, nil
}

// CreatePlaygroup returns JoinPlaygroupResponse (INFO + MLST). BlazeSDK only
// allocates and appends the Playgroup object after this correlated response
// succeeds; NotifyJoinPlaygroup merely updates an object already in that list.
func nfs13CreatePlaygroupReply(request []byte, identity *blazeIdentity, address *Union) ([]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	if packet.Component() != 6 || packet.Command() != 1 || packet.MessageType() != 0 {
		return nil, errors.New("not a Playgroups createPlaygroup request")
	}
	fields, err := nfs13PlaygroupState(identity, address)
	if err != nil {
		return nil, err
	}
	header := append([]byte(nil), packet.Header...)
	header[6], header[7] = 0, 0
	header[8] = header[8]&0x0f | 0x10
	return (Packet{Header: header, Fields: fields}).Encode()
}

func nfs13PlaygroupJoinNotification(identity *blazeIdentity, address *Union) ([]byte, error) {
	fields, err := nfs13PlaygroupState(identity, address)
	if err != nil {
		return nil, err
	}
	fields = append(fields, Field{Tag: "USER", Kind: 0, Value: identity.id})
	// Component 6, notification 51, message type 2, correlation 0.
	header := []byte{0, 0, 0, 6, 0, 51, 0, 0, 0x20, 0, 0, 0}
	return (Packet{Header: header, Fields: fields}).Encode()
}

func userEntitlementsReply(request []byte) ([]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	packet.Header[6], packet.Header[7] = 0, 0
	packet.Header[8] = packet.Header[8]&0x0f | 0x10
	// Authentication/listUserEntitlements2 returns Entitlements::NLST.
	// The local account has no separately managed catalog grants, so return a
	// typed empty Entitlement list while keeping the RPC successful.
	packet.Fields = []Field{
		{Tag: "NLST", Kind: 4, Value: List{Kind: 3, Items: []any{}}},
	}
	return packet.Encode()
}

func utilTelemetryReply(request []byte) ([]byte, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	telemetryField, err := fieldAt(packet.Fields, "TLST", 4)
	if err != nil {
		return nil, err
	}
	telemetry, ok := telemetryField.Value.(List)
	if !ok || telemetry.Kind != 3 {
		return nil, errors.New("TLST is not a struct list")
	}
	for index, item := range telemetry.Items {
		fields, ok := item.([]Field)
		if !ok {
			return nil, fmt.Errorf("TLST[%d] is not a struct", index)
		}
		dirty, err := fieldAt(fields, "DIRT", 0)
		if err != nil {
			return nil, fmt.Errorf("TLST[%d]: %w", index, err)
		}
		dirty.Value = int64(0)
		telemetry.Items[index] = fields
	}
	telemetryField.Value = telemetry
	packet.Header[6], packet.Header[7] = 0, 0
	packet.Header[8] = packet.Header[8]&0x0f | 0x10
	return packet.Encode()
}

func networkAddress(request []byte) (*Union, error) {
	packet, err := decodePacket(request)
	if err != nil {
		return nil, err
	}
	field, err := fieldAt(packet.Fields, "ADDR", 6)
	if err != nil {
		return nil, err
	}
	address, ok := field.Value.(Union)
	if !ok || address.Index != 2 || address.Field == nil || address.Field.Kind != 3 {
		return nil, errors.New("ADDR is not an IP-pair union")
	}
	copyPacket, err := clonePacket(Packet{Header: make([]byte, 12), Fields: []Field{*field}})
	if err != nil {
		return nil, err
	}
	copyField, _ := fieldAt(copyPacket.Fields, "ADDR", 6)
	copyAddress := copyField.Value.(Union)
	return &copyAddress, nil
}

func rewriteNetworkPort(address *Union, port int64) error {
	if address == nil || address.Index != 2 || address.Field == nil ||
		address.Field.Kind != 3 || port < 1 || port > 65535 {
		return errors.New("invalid local game endpoint")
	}
	pair, ok := address.Field.Value.([]Field)
	if !ok {
		return errors.New("network address is not an IP pair")
	}
	for _, tag := range []string{"INIP", "EXIP"} {
		endpoint, err := structField(pair, tag)
		if err != nil {
			return err
		}
		if err = setInteger(endpoint, "PORT", port); err != nil {
			return err
		}
	}
	address.Field.Value = pair
	return nil
}

func rewriteNetworkIP(address *Union, ip int64) error {
	if address == nil || address.Index != 2 || address.Field == nil ||
		address.Field.Kind != 3 || ip < 0 || ip > 0xffffffff {
		return errors.New("invalid local game address")
	}
	pair, ok := address.Field.Value.([]Field)
	if !ok {
		return errors.New("network address is not an IP pair")
	}
	for _, tag := range []string{"INIP", "EXIP"} {
		endpoint, err := structField(pair, tag)
		if err != nil {
			return err
		}
		if err = setInteger(endpoint, "IP", ip); err != nil {
			return err
		}
	}
	address.Field.Value = pair
	return nil
}

func networkAddressText(address *Union) string {
	if address == nil || address.Field == nil {
		return "unknown"
	}
	pair, ok := address.Field.Value.([]Field)
	if !ok {
		return "unknown"
	}
	internal, err := structField(pair, "INIP")
	if err != nil {
		return "unknown"
	}
	ip, ipErr := integerField(internal, "IP")
	port, portErr := integerField(internal, "PORT")
	if ipErr != nil || portErr != nil {
		return "unknown"
	}
	v4 := net.IPv4(byte(uint32(ip)>>24), byte(uint32(ip)>>16), byte(uint32(ip)>>8), byte(uint32(ip)))
	return net.JoinHostPort(v4.String(), fmt.Sprint(port))
}

func networkMachineIDText(address *Union) string {
	if address == nil || address.Field == nil {
		return "unknown"
	}
	pair, ok := address.Field.Value.([]Field)
	if !ok {
		return "unknown"
	}
	machineID, err := integerField(pair, "MACI")
	if err != nil {
		return "unknown"
	}
	return fmt.Sprint(machineID)
}

func applySetupAddress(frame []byte, address *Union) ([]byte, error) {
	if address == nil || address.Field == nil {
		return frame, nil
	}
	packet, err := decodePacket(frame)
	if err != nil {
		return nil, err
	}
	gameFields, err := structField(packet.Fields, "GAME")
	if err != nil {
		return nil, err
	}
	hostsField, err := fieldAt(gameFields, "HNET", 4)
	if err != nil {
		return nil, err
	}
	hosts, ok := hostsField.Value.(List)
	pair, pairOK := address.Field.Value.([]Field)
	if !ok || hosts.Kind != 3 || len(hosts.Items) != 1 || !pairOK {
		return nil, errors.New("unsupported setup host address")
	}
	// Keep MACI exactly as the client reported it. The game transport also uses
	// that client-owned value on the UDP path; virtualizing it only in Blaze
	// metadata makes received peer traffic resolve to the wrong local endpoint.
	hostFields, err := cloneFields(pair)
	if err != nil {
		return nil, err
	}
	hosts.Items[0] = LegacyAddress{Fields: hostFields}
	hostsField.Value = hosts
	rosterField, err := fieldAt(packet.Fields, "PROS", 4)
	if err != nil {
		return nil, err
	}
	roster := rosterField.Value.(List)
	if roster.Kind != 3 || len(roster.Items) != 1 {
		return nil, errors.New("unsupported setup roster")
	}
	player := roster.Items[0].([]Field)
	playerNetwork, err := fieldAt(player, "PNET", 6)
	if err != nil {
		return nil, err
	}
	addressCopyPacket, err := clonePacket(Packet{Header: make([]byte, 12), Fields: []Field{{Tag: "PNET", Kind: 6, Value: *address}}})
	if err != nil {
		return nil, err
	}
	addressCopy, _ := fieldAt(addressCopyPacket.Fields, "PNET", 6)
	playerNetwork.Value = addressCopy.Value
	roster.Items[0] = player
	rosterField.Value = roster
	return packet.Encode()
}

func setNotificationGameID(frame []byte, gameID int64) ([]byte, error) {
	packet, err := decodePacket(frame)
	if err != nil {
		return nil, err
	}
	if field, fieldErr := fieldAt(packet.Fields, "GID", 0); fieldErr == nil {
		field.Value = gameID
	}
	return packet.Encode()
}

func newBlazeServer(advertiseHost string) (*blazeServer, error) {
	var encoded []replayJSONEntry
	if err := json.Unmarshal(blazeReplayJSON, &encoded); err != nil {
		return nil, fmt.Errorf("decode Blaze replay corpus: %w", err)
	}
	corpus := make([]replayEntry, 0, len(encoded))
	for index, item := range encoded {
		request, err := hex.DecodeString(item.Request)
		if err != nil {
			return nil, fmt.Errorf("decode Blaze request %d: %w", index, err)
		}
		entry := replayEntry{request: request}
		for _, encodedReply := range item.Replies {
			reply, err := hex.DecodeString(encodedReply)
			if err != nil {
				return nil, fmt.Errorf("decode Blaze reply %d: %w", index, err)
			}
			entry.replies = append(entry.replies, reply)
		}
		component, command, _, _ := blazeMetadata(entry.request)
		if component == 1 && command == 152 && len(entry.replies) == 1 {
			captured := make([][]byte, 0, 4)
			for frameIndex, encodedFrame := range authenticationSessionFrames {
				frame, err := hex.DecodeString(encodedFrame)
				if err != nil {
					return nil, fmt.Errorf("decode authentication session frame %d: %w", frameIndex, err)
				}
				captured = append(captured, frame)
				if frameIndex == 0 {
					captured = append(captured, entry.replies[0])
				}
			}
			entry.replies = captured
		}
		corpus = append(corpus, entry)
	}
	certificate, err := serviceCertificate(advertiseHost)
	if err != nil {
		return nil, err
	}
	return &blazeServer{
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			// Rivals' Blaze connection can negotiate TLS 1.2, but its older
			// ProtoHttp redirector client offers only TLS 1.1/1.0. The original
			// ZClient service accepts those versions and RSA/CBC suites.
			MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
		},
		corpus:        corpus,
		advertiseHost: advertiseHost,
	}, nil
}

func serviceCertificate(advertiseHost string) (tls.Certificate, error) {
	return makeServiceCertificate(advertiseHost, false)
}

func compactLegacyServiceCertificate(advertiseHost string) (tls.Certificate, error) {
	certificate, err := tls.X509KeyPair(zloWinter15CertPEM, zloWinter15KeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load recovered ZLO redirector identity: %w", err)
	}
	if len(certificate.Certificate) != 1 {
		return tls.Certificate{}, fmt.Errorf("recovered ZLO redirector chain has %d certificates, want one", len(certificate.Certificate))
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse recovered ZLO redirector certificate: %w", err)
	}
	return certificate, nil
}

func makeServiceCertificate(advertiseHost string, compactLegacy bool) (tls.Certificate, error) {
	certificateBlock, _ := pem.Decode(zloTLSCertPEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" {
		return tls.Certificate{}, errors.New("decode embedded ZLO CA certificate")
	}
	caCertificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse embedded ZLO CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(zloTLSKeyPEM)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		return tls.Certificate{}, errors.New("decode embedded ZLO CA private key")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse embedded ZLO CA private key: %w", err)
	}
	if !caKey.PublicKey.Equal(caCertificate.PublicKey) {
		return tls.Certificate{}, errors.New("embedded ZLO CA certificate and key do not match")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate Blaze TLS key: %w", err)
	}
	serial := big.NewInt(1)
	if !compactLegacy {
		serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serial, err = rand.Int(rand.Reader, serialLimit)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("generate Blaze certificate serial: %w", err)
		}
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"RU"},
			Province:           []string{"Herp"},
			Locality:           []string{"Derp"},
			Organization:       []string{"ZLO"},
			OrganizationalUnit: []string{"ZLO"},
			CommonName:         "gosredirector.ea.com",
		},
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.AddDate(10, 0, 0),
		// The captured ZClient redirector leaf uses sha1WithRSAEncryption.
		// This legacy client closes the socket when the replacement chain's
		// shape/signature differs, before emitting a TLS alert.
		SignatureAlgorithm: x509.SHA1WithRSA,
	}
	if !compactLegacy {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{
			"localhost",
			"gosredirector.ea.com",
			"gosredirector.online.ea.com",
			"gosredirector.stest.ea.com",
			"gosredirector.scert.ea.com",
		}
		template.IPAddresses = []net.IP{net.ParseIP(advertiseHost)}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, caCertificate, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create Blaze certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func (s *blazeServer) serve(listener net.Listener) error {
	tlsListener := tls.NewListener(listener, s.tlsConfig)
	for {
		connection, err := tlsListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(connection)
	}
}

func (s *blazeServer) handle(connection net.Conn) {
	defer connection.Close()
	remote := connection.RemoteAddr().String()
	remoteHost, _, _ := net.SplitHostPort(remote)
	localGameNetwork := net.ParseIP(remoteHost).Equal(net.ParseIP(s.advertiseHost))
	log.Printf("Blaze TLS client connected from %s", remote)
	cursor := 0
	var identity *blazeIdentity
	var address *Union
	lobbyKey := ""
	defer func() {
		if lobbyKey != "" && s.registry != nil {
			s.registry.leave(lobbyKey)
		}
	}()
	flushNotifications := func() error {
		if lobbyKey == "" || s.registry == nil {
			return nil
		}
		for _, notification := range s.registry.drain(lobbyKey) {
			if _, err := connection.Write(notification); err != nil {
				return err
			}
			component, command, _, _ := blazeMetadata(notification)
			log.Printf("Blaze pushed component=%d command=%d key=%s", component, command, lobbyKey)
		}
		return nil
	}
	for {
		deadline := 2 * time.Minute
		if lobbyKey != "" {
			deadline = 100 * time.Millisecond
		}
		_ = connection.SetReadDeadline(time.Now().Add(deadline))
		request, err := readBlazeFrame(connection)
		if err != nil {
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() && lobbyKey != "" {
				if err := flushNotifications(); err != nil {
					log.Printf("Blaze notification to %s failed: %v", remote, err)
					return
				}
				continue
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("Blaze client %s disconnected: %v", remote, err)
			}
			return
		}
		component, command, messageType, correlation := blazeMetadata(request)
		if messageType != 0 {
			log.Printf("Blaze client %s sent unsupported message type %d", remote, messageType)
			return
		}
		if component == 0x7802 && command == 35 {
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(userSessionsProbeReply(correlation)); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
			}
			return
		}
		if component == 1 && command == 152 {
			identity, err = s.blazeIdentity(request)
			if err != nil {
				log.Printf("Blaze authentication identity from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze identity remote=%s name=%q id=%d", remote, identity.name, identity.id)
		}
		// NFS13 emits these Authentication lifecycle requests after its initial
		// login and again while reconnecting Autolog. Captured successful runs
		// acknowledge each with an empty correlated success. They are absent or
		// occur at incompatible positions in the ordered NFS14 corpus, so handle
		// them independently of the replay cursor.
		if component == 1 && (command == 32 || command == 70 || command == 260) {
			reply, err := emptySuccessReply(request)
			if err != nil {
				log.Printf("Blaze Authentication lifecycle request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// UserSessions/updateHardwareFlags is a repeatable EmptyMessage RPC. NFS13
		// sends HFLG=0 during initial setup and HFLG=1 immediately after Autolog
		// login. The replay contains only one compatible sample at the current
		// cursor, so treating the second payload as a new ordered request closes the
		// authenticated Blaze session before matchmaking begins.
		if component == 0x7802 && command == 8 {
			reply, err := emptySuccessReply(request)
			if err != nil {
				log.Printf("Blaze hardware-flags update from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		if component == 0x7802 && command == 20 {
			if parsed, parseErr := networkAddress(request); parseErr == nil {
				address = parsed
				if identity != nil && identity.gamePort != 0 {
					if parseErr = rewriteNetworkPort(address, identity.gamePort); parseErr != nil {
						log.Printf("Blaze game endpoint for %s is invalid: %v", identity.name, parseErr)
						return
					}
					if localGameNetwork {
						if parseErr = rewriteNetworkIP(address, gameVirtualAddressForPort(identity.gamePort)); parseErr != nil {
							log.Printf("Blaze local game address for %s is invalid: %v", identity.name, parseErr)
							return
						}
					}
				}
				name := "unidentified"
				if identity != nil {
					name = identity.name
				}
				log.Printf("Blaze game endpoint name=%q endpoint=%s machine=%s",
					name, networkAddressText(address), networkMachineIDText(address))
			}
		}
		if component == 0x0802 && command == 20 {
			reply, err := softwareProductReply(request)
			if err != nil {
				log.Printf("Blaze software-product request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		if component == 9 && command == 20 {
			reply, err := utilTelemetryReply(request)
			if err != nil {
				log.Printf("Blaze Util telemetry request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// The finite replay contains a periodic UserSessions notification bundled
		// with one Utility/ping sample. Selecting that entry by cursor causes
		// NFS13 to receive an unrelated session update on its first multiplayer
		// keepalive and it tears down Autolog on the following ping. A ping is a
		// standalone RPC: always return one correlated reply with current server
		// time instead of inheriting adjacent traffic from the capture.
		if s.nfs13 && component == 9 && command == 2 {
			reply, err := utilPingReply(request, time.Now().Unix())
			if err != nil {
				log.Printf("Blaze Utility ping from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// NFS13 asks Utility/fetchClientConfig twice during startup, once for
		// "Url" and once for "Game". Treat these as independent repeatable
		// requests: the ordered NFS14 corpus contains command 9/1 later in its
		// session, but that response is not compatible with NFS13's keys.
		if component == 9 && command == 1 {
			autologURL := ""
			if s.nfs13 {
				autologURL = nfs13AutologBaseURL(s.advertiseHost)
			}
			reply, err := utilClientConfigReply(request, autologURL)
			if err != nil {
				log.Printf("Blaze Utility config request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// Util/setClientMetrics is a one-way metrics update with an EmptyMessage
		// success response. It appears after longer multiplayer sessions and is
		// not represented in the finite startup replay corpus.
		if component == 9 && command == 22 {
			reply, err := emptySuccessReply(request)
			if err != nil {
				log.Printf("Blaze client-metrics request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// NFS13 sends its six RoadRules records through RspComponent/updatePurchase
		// after the initial online-state setup. Blaze defines command 11 as an
		// EmptyMessage -> EmptyMessage RPC; the title-specific request body does not
		// change that response contract. Leaving it to the finite NFS14 replay has no
		// match and closes the primary Blaze connection, which is what eventually
		// surfaces as an Autolog disconnect while idling in the multiplayer menu.
		if s.nfs13 && component == 0x0801 && command == 11 {
			reply, err := emptySuccessReply(request)
			if err != nil {
				log.Printf("Blaze NFS13 RoadRules update from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// NFS13 requests one subscribed type-1 association list. The NFS14 replay
		// answers with five list descriptors and uses its title-specific FLGS=4,
		// which NFS13 does not recognize as ListStatusFlags::Subscribed. Return the
		// Blaze3 friend-list contract the live request asks for so the title can
		// finish its social initialization before creating a friends game.
		if s.nfs13 && component == 25 && command == 6 {
			reply, err := nfs13AssociationListsReply(request, identity)
			if err != nil {
				log.Printf("Blaze NFS13 association-list request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// CreatePlaygroup is not void: BlazeSDK expects JoinPlaygroupResponse and
		// only then appends the new object to PlaygroupAPI::mPlaygroupList. A bare
		// NotifyJoinPlaygroup cannot bootstrap that list; its handler asserts when
		// the group ID is not already present.
		if s.nfs13 && component == 6 && command == 1 {
			reply, err := nfs13CreatePlaygroupReply(request, identity, address)
			if err != nil {
				log.Printf("Blaze NFS13 create-playgroup request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=2", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			notification, err := nfs13PlaygroupJoinNotification(identity, address)
			if err != nil {
				log.Printf("Blaze NFS13 create-playgroup notification for %s is invalid: %v", remote, err)
				return
			}
			if _, err := connection.Write(notification); err != nil {
				log.Printf("Blaze playgroup notification to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// The remaining Playgroups control RPCs are void in the Blaze3 contract.
		if s.nfs13 && component == 6 && command >= 2 && command <= 11 {
			reply, err := emptySuccessReply(request)
			if err != nil {
				log.Printf("Blaze NFS13 playgroup request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// AssociationLists/addUsersToList can be emitted while a second local
		// user synchronizes its social state. It is absent from the single-user
		// replay corpus, but failing it tears down the main Blaze connection and
		// surfaces as a network error during an otherwise valid lobby join.
		if component == 25 && command == 1 {
			reply, err := associationUpdateReply(request)
			if err != nil {
				log.Printf("Blaze association-list update from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// GameManager/addAdminPlayer is a void lifecycle update issued by the
		// host after a joining player finishes mesh setup.
		if component == 4 && command == 106 {
			reply, err := emptySuccessReply(request)
			if err != nil {
				log.Printf("Blaze add-admin request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// GameManager/cancelMatchmaking is also a void RPC. It can follow a search
		// cancelled by the player or by the title's own timeout and must not tear
		// down the otherwise healthy Blaze transport.
		if component == 4 && command == 14 {
			reply, err := emptySuccessReply(request)
			if err != nil {
				log.Printf("Blaze cancel-matchmaking request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// NFS13 finalizes both a public match and a create-only friends game
		// immediately after NotifyGameSetup. This is a void lifecycle RPC; the
		// captured request embeds the newly assigned GID, so exact replay cannot
		// match it and previously closed the primary Blaze connection.
		if component == 4 && command == 15 {
			reply, err := emptySuccessReply(request)
			if err != nil {
				log.Printf("Blaze finalize-game request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// GameManager/destroyGame returns DestroyGameResponse rather than an
		// EmptyMessage. NFS13 uses it to abandon a game setup it cannot accept;
		// dropping this cleanup RPC turns that rejection into a full Autolog
		// disconnect and prevents us from observing the client's next state.
		if component == 4 && command == 2 {
			reply, err := destroyGameReply(request)
			if err != nil {
				log.Printf("Blaze destroy-game request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			if lobbyKey != "" && s.registry != nil {
				s.registry.leave(lobbyKey)
				lobbyKey = ""
			}
			continue
		}
		// Removing the local player is also a void RPC. Release the registry
		// membership after acknowledging it so a later friends-game attempt by
		// the same local identity does not collide with stale lobby state.
		if component == 4 && command == 11 {
			reply, err := emptySuccessReply(request)
			if err != nil {
				log.Printf("Blaze remove-player request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			if lobbyKey != "" && s.registry != nil {
				s.registry.leave(lobbyKey)
				lobbyKey = ""
			}
			continue
		}
		// GameManager/updateMeshConnection reports the connection state between
		// the local connection group and another member after a lobby join. Its
		// Blaze RPC response is void; the peer-state data is carried by the
		// request and subsequent GameManager notifications.
		if component == 4 && command == 29 {
			reply, err := emptySuccessReply(request)
			if err != nil {
				log.Printf("Blaze mesh-connection request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			if lobbyKey != "" && s.registry != nil {
				if err := s.registry.updateMesh(lobbyKey, request); err != nil {
					log.Printf("Blaze mesh-connection update rejected key=%s: %v", lobbyKey, err)
				} else if err := flushNotifications(); err != nil {
					log.Printf("Blaze notification to %s failed: %v", remote, err)
					return
				}
			}
			continue
		}
		// The private ZClient component's commands 29 and 21 carry only BLID
		// and record consecutive client-side state transitions. The real
		// service returns a correlated void success for each.
		if component == 0x0802 && (command == 29 || command == 21) {
			reply, err := emptySuccessReply(request)
			if err != nil {
				log.Printf("Blaze ZClient state request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		// Authentication/listUserEntitlements2 is requested after some longer
		// session/reporting paths but is absent from the startup replay corpus.
		if component == 1 && command == 29 {
			reply, err := userEntitlementsReply(request)
			if err != nil {
				log.Printf("Blaze user-entitlements request from %s is invalid: %v", remote, err)
				return
			}
			log.Printf("Blaze request component=%d command=%d correlation=%d replies=1", component, command, correlation)
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
			continue
		}
		var replies [][]byte
		if component == 4 && command == 3 {
			replies, err = advanceGameStateReplies(request)
			if err != nil {
				log.Printf("Blaze advance-state request from %s is invalid: %v", remote, err)
				return
			}
		} else if component == 4 && command == 4 {
			replies, err = setGameSettingsReplies(request)
			if err != nil {
				log.Printf("Blaze set-game-settings request from %s is invalid: %v", remote, err)
				return
			}
		} else if s.nfs13 && component == 4 && command == 25 {
			replies, err = s.nfs13ResetDedicatedServerReplies(request)
			if err != nil {
				log.Printf("Blaze NFS13 reset-dedicated-server request from %s is invalid: %v", remote, err)
				return
			}
		} else {
			index, exact, reused := s.findReplay(request, cursor)
			// NFS13 expects UpdateNetworkInfo to publish both its correlated
			// success and a UserSessionExtendedData notification every time it
			// refreshes the endpoint. Later NFS14 corpus entries contain only the
			// success frame; selecting one leaves NFS13 waiting for online state
			// until its reconnect timeout expires.
			if s.nfs13 && component == 0x7802 && command == 20 {
				if nfs13Index := s.nfs13NetworkInfoReplay(); nfs13Index >= 0 {
					index = nfs13Index
					exact = false
					reused = nfs13Index < cursor
				}
			}
			if index < 0 {
				log.Printf("Blaze replay has no response for component=%d command=%d correlation=%d", component, command, correlation)
				return
			}
			if !exact && reused {
				log.Printf("Blaze replay payload differed; reusing component=%d command=%d entry=%d", component, command, index)
			} else if !exact {
				log.Printf("Blaze replay payload differed; using ordered component=%d command=%d entry=%d", component, command, index)
			} else if reused {
				log.Printf("Blaze replay reusing repeatable component=%d command=%d entry=%d", component, command, index)
			}
			entry := s.corpus[index]
			if index >= cursor {
				cursor = index + 1
			}
			replies = entry.replies
		}
		log.Printf("Blaze request component=%d command=%d correlation=%d replies=%d", component, command, correlation, len(replies))
		for _, normalizedReply := range replies {
			reply, refreshed, err := personalizeReplayReply(normalizedReply, time.Now().Unix(), identity)
			if err != nil {
				log.Printf("Blaze replay time refresh failed: %v", err)
				return
			}
			replyComponent, replyCommand, replyType, _ := blazeMetadata(reply)
			if s.nfs13 && component == 7 && (command == 4 || command == 16) {
				reply, err = nfs13StatsReply(request, reply)
				if err != nil {
					log.Printf("Blaze NFS13 Stats compatibility rewrite failed: %v", err)
					return
				}
				replyComponent, replyCommand, replyType, _ = blazeMetadata(reply)
			}
			if s.nfs13 && component == 1 && command == 152 &&
				replyComponent == 0x7802 && (replyCommand == 2 || replyCommand == 5) && replyType == 2 {
				reply, err = personalizeNFS13UserSessionNotification(reply, identity)
				if err != nil {
					log.Printf("Blaze NFS13 UserSessions identity rewrite failed: %v", err)
					return
				}
			}
			if s.nfs13 && s.rewritePreAuth && component == 9 && command == 7 &&
				replyComponent == 9 && replyCommand == 7 && replyType == 1 {
				reply, err = nfs13PreAuthReply(request, reply, s.advertiseHost)
				if err != nil {
					log.Printf("Blaze NFS13 pre-auth rewrite failed: %v", err)
					return
				}
			}
			if component == 4 && (command == 13 || s.nfs13 && command == 25) &&
				replyComponent == 4 && replyCommand == 20 && replyType == 2 && s.registry != nil {
				if identity == nil {
					log.Printf("Blaze game setup from %s has no authenticated identity", remote)
					return
				}
				reply, err = applySetupAddress(reply, address)
				if err != nil {
					log.Printf("Blaze game setup address from %s is invalid: %v", remote, err)
					return
				}
				matchExisting := true
				if command == 25 {
					reply, err = nfs13ResetDedicatedServerSetup(request, reply)
					if err != nil {
						log.Printf("Blaze NFS13 friends-game setup from %s is invalid: %v", remote, err)
						return
					}
					matchExisting = false
				} else if s.nfs13 {
					var createOnly bool
					reply, createOnly, err = nfs13MatchmakingSetup(request, reply)
					if err != nil {
						log.Printf("Blaze NFS13 matchmaking setup from %s is invalid: %v", remote, err)
						return
					}
					matchExisting = !createOnly
				}
				key := "blaze:" + identity.name
				reply, err = s.registry.exchangeSetup(key, reply, matchExisting)
				if err != nil {
					log.Printf("Blaze game setup rejected key=%s: %v", key, err)
					return
				}
				lobbyKey = key
			}
			if lobbyKey != "" && replyComponent == 4 && replyType == 2 && replyCommand != 20 && s.registry != nil {
				gameID := s.registry.gameID(lobbyKey)
				if gameID != 0 {
					reply, err = setNotificationGameID(reply, gameID)
					if err != nil {
						log.Printf("Blaze game notification rewrite failed key=%s: %v", lobbyKey, err)
						return
					}
				}
				forwarded, exchangeErr := s.registry.exchange(lobbyKey, reply)
				if exchangeErr != nil {
					log.Printf("Blaze game notification rejected key=%s: %v", lobbyKey, exchangeErr)
					return
				}
				if len(forwarded) == 0 {
					continue
				}
				reply = forwarded
			}
			if refreshed != 0 {
				log.Printf("Blaze replay refreshed %d time field(s)", refreshed)
			}
			if replyType == 1 || replyType == 3 {
				setBlazeCorrelation(reply, correlation)
			}
			if _, err := connection.Write(reply); err != nil {
				log.Printf("Blaze reply to %s failed: %v", remote, err)
				return
			}
		}
		if err := flushNotifications(); err != nil {
			log.Printf("Blaze notification to %s failed: %v", remote, err)
			return
		}
	}
}

func (s *blazeServer) nfs13NetworkInfoReplay() int {
	for index, entry := range s.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component != 0x7802 || command != 20 || len(entry.replies) != 2 {
			continue
		}
		notificationComponent, notificationCommand, notificationType, _ := blazeMetadata(entry.replies[1])
		if notificationComponent == 0x7802 && notificationCommand == 1 && notificationType == 2 {
			return index
		}
	}
	return -1
}

func (s *blazeServer) nfs13GameSetupReplay() []byte {
	for _, entry := range s.corpus {
		for _, reply := range entry.replies {
			component, command, messageType, _ := blazeMetadata(reply)
			if component == 4 && command == 20 && messageType == 2 {
				return append([]byte(nil), reply...)
			}
		}
	}
	return nil
}

func (s *blazeServer) nfs13ResetDedicatedServerReplies(request []byte) ([][]byte, error) {
	component, command, messageType, _ := blazeMetadata(request)
	if component != 4 || command != 25 || messageType != 0 {
		return nil, errors.New("not a GameManager reset-dedicated-server request")
	}
	reply, err := emptySuccessReply(request)
	if err != nil {
		return nil, err
	}
	setup := s.nfs13GameSetupReplay()
	if len(setup) == 0 {
		return nil, errors.New("replay corpus lacks a GameManager setup notification")
	}
	return [][]byte{reply, setup}, nil
}

func prepareReplayReply(frame []byte, now int64) ([]byte, int, error) {
	packet, err := decodePacket(frame)
	if err != nil {
		return nil, 0, err
	}
	refreshed := refreshTimeFields(packet.Fields, now)
	if refreshed == 0 {
		return append([]byte(nil), frame...), 0, nil
	}
	encoded, err := packet.Encode()
	return encoded, refreshed, err
}

func refreshTimeFields(fields []Field, now int64) int {
	refreshed := 0
	for index := range fields {
		field := &fields[index]
		if field.Kind == 0 && (field.Tag == "STIM" || field.Tag == "LLOG" || field.Tag == "LAST") {
			field.Value = now
			refreshed++
		}
		switch value := field.Value.(type) {
		case []Field:
			refreshed += refreshTimeFields(value, now)
		case List:
			if value.Kind == 3 {
				for itemIndex := range value.Items {
					if nested, ok := value.Items[itemIndex].([]Field); ok {
						refreshed += refreshTimeFields(nested, now)
					}
				}
			}
			field.Value = value
		case Union:
			if value.Field != nil {
				nested := []Field{*value.Field}
				refreshed += refreshTimeFields(nested, now)
				*value.Field = nested[0]
			}
			field.Value = value
		case Variable:
			if value.Field != nil {
				nested := []Field{*value.Field}
				refreshed += refreshTimeFields(nested, now)
				*value.Field = nested[0]
			}
			field.Value = value
		}
	}
	return refreshed
}

func (s *blazeServer) findReplay(request []byte, cursor int) (index int, exact bool, reused bool) {
	normalized := normalizeBlazeCorrelation(request)
	for index := cursor; index < len(s.corpus); index++ {
		if string(s.corpus[index].request) == string(normalized) {
			return index, true, false
		}
	}
	component, command, _, _ := blazeMetadata(request)
	for index := cursor; index < len(s.corpus); index++ {
		candidateComponent, candidateCommand, _, _ := blazeMetadata(s.corpus[index].request)
		if candidateComponent == component && candidateCommand == command {
			return index, false, false
		}
	}
	// Polls and keepalives are repeated indefinitely by the client, while a
	// finite capture naturally contains only a few samples. Reuse the most
	// recent byte-identical request after the ordered replay is exhausted.
	// Searching backwards selects the response from the latest captured state.
	for index := len(s.corpus) - 1; index >= 0; index-- {
		if string(s.corpus[index].request) == string(normalized) {
			return index, true, true
		}
	}
	// UserSettingsLoad, UpdateNetworkInfo, the private UserSessions command 13,
	// AssociationLists/getLists, GameManager/startMatchmaking, and
	// GameReporting/submitGameReport are sent repeatedly with intentionally
	// different setting names, identity, measurement, list filters, matchmaking
	// criteria, or report data. The captured UserSettingsLoad result is the same
	// "not found" error for every requested key, while the other RPC responses
	// are likewise used as typed templates and rewritten from live state. Reuse
	// the latest response bundle after the ordered cursor has advanced. The game
	// report bundle includes its result notice.
	if (component == 0x7802 && (command == 13 || command == 20)) ||
		(component == 9 && (command == 8 || command == 10)) ||
		(component == 25 && command == 6) ||
		(component == 4 && command == 13) ||
		(component == 28 && command == 2) {
		for index := len(s.corpus) - 1; index >= 0; index-- {
			candidateComponent, candidateCommand, _, _ := blazeMetadata(s.corpus[index].request)
			if candidateComponent == component && candidateCommand == command {
				return index, false, true
			}
		}
	}
	return -1, false, false
}

func readBlazeFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, 12)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	flags := header[9] >> 4
	extraSize := 0
	if flags&1 != 0 {
		extraSize += 2
	}
	if flags&2 != 0 {
		if flags&8 != 0 {
			extraSize += 8
		} else {
			extraSize += 4
		}
	} else if flags&8 != 0 {
		return nil, errors.New("invalid Blaze frame flags")
	}
	extra := make([]byte, extraSize)
	if _, err := io.ReadFull(reader, extra); err != nil {
		return nil, err
	}
	bodySize := int(header[0])<<8 | int(header[1])
	if flags&1 != 0 {
		bodySize |= (int(extra[0])<<8 | int(extra[1])) << 16
	}
	if bodySize < 0 || bodySize > maxBlazeFrame {
		return nil, fmt.Errorf("invalid Blaze body size %d", bodySize)
	}
	body := make([]byte, bodySize)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	frame := append(header, extra...)
	return append(frame, body...), nil
}

func blazeMetadata(frame []byte) (component, command uint16, messageType byte, correlation uint32) {
	component = uint16(frame[2])<<8 | uint16(frame[3])
	command = uint16(frame[4])<<8 | uint16(frame[5])
	messageType = frame[8] >> 4
	correlation = uint32(frame[9]&0x0f)<<16 | uint32(frame[10])<<8 | uint32(frame[11])
	return
}

func normalizeBlazeCorrelation(frame []byte) []byte {
	normalized := append([]byte(nil), frame...)
	setBlazeCorrelation(normalized, 0)
	return normalized
}

func setBlazeCorrelation(frame []byte, correlation uint32) {
	frame[9] = frame[9]&0xf0 | byte(correlation>>16)&0x0f
	frame[10] = byte(correlation >> 8)
	frame[11] = byte(correlation)
}
