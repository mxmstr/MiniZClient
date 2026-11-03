package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

type queuedEvent struct {
	Sequence uint32
	Data     []byte
}
type peer struct {
	Key                      string
	Player                   []Field
	Seen                     time.Time
	GameID                   int64
	Events                   []queuedEvent
	Sequence, Delivered      uint32
	PendingSince             time.Time
	Warned                   bool
	SetupRequest, SetupReply []byte
}
type game struct {
	ID            int64
	Host          string
	Data          []Field
	Compatibility []byte
	Capacity      int
	Matchable     bool
	Members       []string
	Completed     map[int64]bool
}
type registry struct {
	mu                       sync.Mutex
	ttl                      time.Duration
	peers                    map[string]*peer
	games                    map[int64]*game
	nextGameID               int64
	lanAddresses, peerHosted bool
}

func newRegistry(ttl time.Duration, lan, hosted bool) *registry {
	return &registry{ttl: ttl, peers: map[string]*peer{}, games: map[int64]*game{}, nextGameID: 0x10000, lanAddresses: lan, peerHosted: hosted}
}

func listField(fields []Field, tag string) (List, error) {
	f, e := fieldAt(fields, tag, 4)
	if e != nil {
		return List{}, e
	}
	v, ok := f.Value.(List)
	if !ok {
		return List{}, fmt.Errorf("bad list %s", tag)
	}
	return v, nil
}
func mapField(fields []Field, tag string) (MapValue, error) {
	f, e := fieldAt(fields, tag, 5)
	if e != nil {
		return MapValue{}, e
	}
	v, ok := f.Value.(MapValue)
	if !ok {
		return MapValue{}, fmt.Errorf("bad map %s", tag)
	}
	return v, nil
}
func unionField(fields []Field, tag string) (Union, error) {
	f, e := fieldAt(fields, tag, 6)
	if e != nil {
		return Union{}, e
	}
	v, ok := f.Value.(Union)
	if !ok {
		return Union{}, fmt.Errorf("bad union %s", tag)
	}
	return v, nil
}
func bytesField(fields []Field, tag string) ([]byte, error) {
	f, e := fieldAt(fields, tag)
	if e != nil {
		return nil, e
	}
	v, ok := f.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("bad bytes %s", tag)
	}
	return v, nil
}
func fieldsFromItem(item any) ([]Field, error) {
	v, ok := item.([]Field)
	if !ok {
		return nil, fmt.Errorf("expected struct, got %T", item)
	}
	return v, nil
}
func notification(command uint16, fields []Field) ([]byte, error) {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[2:4], 4)
	binary.BigEndian.PutUint16(h[4:6], command)
	h[8] = 0x20
	return (Packet{Header: h, Fields: fields}).Encode()
}

func (r *registry) queue(p *peer, raw []byte) error {
	if len(p.Events) >= 256 {
		return errors.New("notification backlog; reconnect client")
	}
	if len(p.Events) == 0 {
		p.PendingSince = time.Now()
		p.Warned = false
	}
	p.Sequence++
	p.Events = append(p.Events, queuedEvent{p.Sequence, append([]byte(nil), raw...)})
	return nil
}
func (r *registry) broadcast(g *game, raw []byte, exclude string) error {
	for _, key := range g.Members {
		if key != exclude {
			if e := r.queue(r.peers[key], raw); e != nil {
				return e
			}
		}
	}
	return nil
}

func (r *registry) completePlayerLocked(g *game, pid int64) error {
	if g.Completed[pid] {
		return nil
	}
	var joined *peer
	for _, member := range g.Members {
		candidate := r.peers[member]
		if candidate != nil && mustInteger(candidate.Player, "PID") == pid {
			joined = candidate
			break
		}
	}
	if joined == nil {
		return errors.New("unknown mesh target")
	}
	stateNotice, err := notification(116, []Field{{"GID", 0, g.ID}, {"PID", 0, pid}, {"STAT", 0, int64(4)}})
	if err != nil {
		return err
	}
	completedNotice, err := notification(30, []Field{{"GID", 0, g.ID}, {"PID", 0, pid}})
	if err != nil {
		return err
	}
	if err = r.broadcast(g, stateNotice, ""); err != nil {
		return err
	}
	if err = r.broadcast(g, completedNotice, ""); err != nil {
		return err
	}
	_ = setInteger(joined.Player, "STAT", 4)
	g.Completed[pid] = true
	log.Printf("mesh connected pid=%d game=%d", pid, g.ID)
	return nil
}

func (r *registry) removeLocked(key string) {
	p := r.peers[key]
	if p == nil {
		return
	}
	g := r.games[p.GameID]
	if g != nil {
		if g.Host == key {
			raw, _ := notification(16, []Field{{"GID", 0, g.ID}, {"REAS", 0, int64(0)}})
			for _, member := range g.Members {
				if member != key {
					target := r.peers[member]
					target.Events = nil
					_ = r.queue(target, raw)
				}
				r.peers[member].GameID = 0
			}
			delete(r.games, g.ID)
		} else {
			for i, member := range g.Members {
				if member == key {
					g.Members = append(g.Members[:i], g.Members[i+1:]...)
					break
				}
			}
			raw, _ := notification(40, []Field{{"CNTX", 0, int64(0)}, {"GID", 0, g.ID}, {"PID", 0, mustInteger(p.Player, "PID")}, {"REAS", 0, int64(1)}})
			_ = r.broadcast(g, raw, "")
		}
	}
	delete(r.peers, key)
}
func (r *registry) expireLocked(now time.Time, warn bool) {
	for key, p := range r.peers {
		if warn && len(p.Events) > 0 && !p.Warned && now.Sub(p.PendingSince) >= 10*time.Second {
			log.Printf("unacknowledged notifications key=%s pending=%d", key, len(p.Events))
			p.Warned = true
		}
		if now.Sub(p.Seen) > r.ttl {
			log.Printf("expired key=%s", key)
			r.removeLocked(key)
		}
	}
}

func mustInteger(fields []Field, tag string) int64 {
	v, e := integerField(fields, tag)
	if e != nil {
		panic(e)
	}
	return v
}
func cloneFields(fields []Field) ([]Field, error) {
	h := make([]byte, 12)
	p := Packet{Header: h, Fields: fields}
	c, e := clonePacket(p)
	return c.Fields, e
}

func normalizeAddress(fields []Field) (string, error) {
	internal, e := structField(fields, "INIP")
	if e != nil {
		return "", e
	}
	ip, e := integerField(internal, "IP")
	if e != nil {
		return "", e
	}
	port, e := integerField(internal, "PORT")
	if e != nil {
		return "", e
	}
	v4 := net.IPv4(byte(uint32(ip)>>24), byte(uint32(ip)>>16), byte(uint32(ip)>>8), byte(uint32(ip)))
	if ip == 0 || uint32(ip) == 0xffffffff || v4.IsMulticast() || port < 1 || port > 65535 {
		return "", errors.New("invalid LAN peer endpoint")
	}
	external, e := structField(fields, "EXIP")
	if e != nil {
		return "", e
	}
	if e = setInteger(external, "IP", ip); e != nil {
		return "", e
	}
	if e = setInteger(external, "PORT", port); e != nil {
		return "", e
	}
	return fmt.Sprintf("%s:%d", v4, port), nil
}

func (r *registry) normalizeLAN(packet *Packet) error {
	gameFields, e := structField(packet.Fields, "GAME")
	if e != nil {
		return e
	}
	hosts, e := listField(gameFields, "HNET")
	if e != nil || hosts.Kind != 3 || len(hosts.Items) != 1 {
		return errors.New("unsupported LAN host address format")
	}
	legacy, ok := hosts.Items[0].(LegacyAddress)
	if !ok {
		return errors.New("unsupported LAN host address format")
	}
	host, e := normalizeAddress(legacy.Fields)
	if e != nil {
		return e
	}
	roster, e := listField(packet.Fields, "PROS")
	if e != nil || roster.Kind != 3 || len(roster.Items) != 1 {
		return errors.New("expected original one-player setup")
	}
	player, e := fieldsFromItem(roster.Items[0])
	if e != nil {
		return e
	}
	u, e := unionField(player, "PNET")
	if e != nil || u.Index != 2 || u.Field == nil || u.Field.Kind != 3 {
		return errors.New("unsupported LAN player address format")
	}
	pair, ok := u.Field.Value.([]Field)
	if !ok {
		return errors.New("unsupported LAN player address format")
	}
	endpoint, e := normalizeAddress(pair)
	if e != nil {
		return e
	}
	if host != endpoint {
		return errors.New("LAN host/player endpoint mismatch")
	}
	return nil
}

func (r *registry) setupLocked(key string, original Packet, raw []byte, matchExisting bool) ([]byte, error) {
	packet, e := clonePacket(original)
	if e != nil {
		return nil, e
	}
	if r.lanAddresses {
		if e = r.normalizeLAN(&packet); e != nil {
			return nil, e
		}
	}
	gameFields, e := structField(packet.Fields, "GAME")
	if e != nil {
		return nil, e
	}
	if r.peerHosted {
		topology, e := integerField(gameFields, "NTOP")
		if e != nil {
			return nil, e
		}
		if topology != 0 && topology != 133 {
			return nil, errors.New("unsupported source topology for direct peer host")
		}
		if e = setInteger(gameFields, "NTOP", 0); e != nil {
			return nil, e
		}
	}
	roster, e := listField(packet.Fields, "PROS")
	if e != nil || roster.Kind != 3 || len(roster.Items) != 1 {
		return nil, errors.New("expected original one-player setup")
	}
	reason, e := unionField(packet.Fields, "REAS")
	if e != nil || (reason.Index != 1 && reason.Index != 3) ||
		reason.Field == nil || reason.Field.Kind != 3 {
		return nil, errors.New("unsupported game setup reason")
	}
	attrs, e := mapField(gameFields, "ATTR")
	if e != nil || attrs.KeyKind != 1 || attrs.ValueKind != 1 {
		return nil, errors.New("only explicitly Public matchmaking supported")
	}
	public := false
	for _, pair := range attrs.Pairs {
		if bytes.Equal(pair.Key.([]byte), []byte("gameMembershipRequirements")) && bytes.Equal(pair.Value.([]byte), []byte("Public")) {
			public = true
		}
	}
	if matchExisting && !public {
		return nil, errors.New("only explicitly Public matchmaking supported")
	}
	player, e := fieldsFromItem(roster.Items[0])
	if e != nil {
		return nil, e
	}
	pid, e := integerField(player, "PID")
	if e != nil {
		return nil, e
	}
	cong, e := integerField(player, "CONG")
	if e != nil {
		return nil, e
	}
	if pid <= 0 || cong <= 0 {
		return nil, errors.New("invalid player identity")
	}
	for _, role := range []string{"PHST", "THST"} {
		host, e := structField(gameFields, role)
		if e != nil {
			return nil, e
		}
		hpid, _ := integerField(host, "HPID")
		hcong, _ := integerField(host, "CONG")
		if hpid != pid || hcong != cong {
			return nil, errors.New("template host mismatch")
		}
	}
	for _, tag := range []string{"GID", "SID", "SLOT", "STAT", "UID"} {
		if _, e = integerField(player, tag); e != nil {
			return nil, e
		}
	}
	slotType, _ := integerField(player, "SLOT")
	if slotType != 0 {
		return nil, errors.New("only public participant slots supported")
	}
	if _, e = unionField(player, "PNET"); e != nil {
		return nil, e
	}
	capList, e := listField(gameFields, "CAP")
	if e != nil || capList.Kind != 0 || len(capList.Items) == 0 {
		return nil, errors.New("unsupported capacity")
	}
	capacity64, ok := capList.Items[0].(int64)
	if !ok || capacity64 < 2 || capacity64 > 64 {
		return nil, errors.New("unsupported capacity")
	}
	var compatFields []Field
	for _, tag := range []string{"ATTR", "VSTR", "ESNM", "GPVH", "NTOP", "VOIP", "GSET", "CAP", "RNFO", "TIDS"} {
		f, e := fieldAt(gameFields, tag)
		if e != nil {
			return nil, e
		}
		compatFields = append(compatFields, *f)
	}
	compat, e := encodeFields(compatFields, 0)
	if e != nil {
		return nil, e
	}
	for _, old := range r.peers {
		if mustInteger(old.Player, "PID") == pid || mustInteger(old.Player, "CONG") == cong {
			return nil, errors.New("identity already active; wait for expiry or leave first")
		}
	}
	if len(r.peers) >= 128 {
		return nil, errors.New("coordinator capacity reached")
	}
	var selected *game
	ids := make([]int64, 0, len(r.games))
	for id := range r.games {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if matchExisting {
		for _, id := range ids {
			candidate := r.games[id]
			if candidate.Matchable && bytes.Equal(candidate.Compatibility, compat) && len(candidate.Members) < candidate.Capacity {
				selected = candidate
				break
			}
		}
	}
	created := selected == nil
	if created {
		data, e := cloneFields(gameFields)
		if e != nil {
			return nil, e
		}
		selected = &game{ID: r.nextGameID, Host: key, Data: data, Compatibility: compat, Capacity: int(capacity64), Matchable: matchExisting, Completed: map[int64]bool{}}
		r.nextGameID++
		_ = setInteger(selected.Data, "GID", selected.ID)
		for _, role := range []string{"PHST", "THST"} {
			h, _ := structField(selected.Data, role)
			_ = setInteger(h, "HSLT", 0)
			_ = setInteger(h, "CSID", 0)
		}
	}
	occupied := map[int64]bool{}
	for _, member := range selected.Members {
		occupied[mustInteger(r.peers[member].Player, "SID")] = true
	}
	slot := int64(0)
	for occupied[slot] {
		slot++
	}
	player, e = cloneFields(player)
	if e != nil {
		return nil, e
	}
	_ = setInteger(player, "GID", selected.ID)
	_ = setInteger(player, "SID", slot)
	if f, err := fieldAt(player, "CSID"); err == nil {
		f.Value = slot
	} else {
		index := sort.Search(len(player), func(i int) bool { return player[i].Tag > "CSID" })
		player = append(player, Field{})
		copy(player[index+1:], player[index:])
		player[index] = Field{"CSID", 0, slot}
	}
	if created {
		_ = setInteger(player, "STAT", 4)
	} else {
		_ = setInteger(player, "STAT", 2)
	}
	response, e := clonePacket(packet)
	if e != nil {
		return nil, e
	}
	responseGame, _ := fieldAt(response.Fields, "GAME", 3)
	responseGameFields, e := cloneFields(selected.Data)
	if e != nil {
		return nil, e
	}
	responseGame.Value = responseGameFields
	responseRoster, _ := fieldAt(response.Fields, "PROS", 4)
	items := make([]any, 0, len(selected.Members)+1)
	for _, member := range selected.Members {
		c, _ := cloneFields(r.peers[member].Player)
		items = append(items, c)
	}
	cp, e := cloneFields(player)
	if e != nil {
		return nil, e
	}
	items = append(items, cp)
	responseRoster.Value = List{Kind: 3, Items: items}
	responseReason, _ := unionField(response.Fields, "REAS")
	context := responseReason.Field.Value.([]Field)
	if responseReason.Index == 3 {
		if created {
			_ = setInteger(context, "RSLT", 0)
		} else {
			_ = setInteger(context, "RSLT", 2)
		}
	}
	responseField, _ := fieldAt(response.Fields, "REAS", 6)
	responseReason.Field.Value = context
	responseField.Value = responseReason
	result, e := response.Encode()
	if e != nil {
		return nil, e
	}
	notice, e := notification(21, []Field{{"GID", 0, selected.ID}, {"PDAT", 3, player}})
	if e != nil {
		return nil, e
	}
	for _, member := range selected.Members {
		if len(r.peers[member].Events) >= 256 {
			return nil, errors.New("host notification backlog")
		}
	}
	if created {
		r.games[selected.ID] = selected
	}
	r.peers[key] = &peer{Key: key, Player: player, Seen: time.Now(), GameID: selected.ID, SetupRequest: append([]byte(nil), raw...), SetupReply: append([]byte(nil), result...)}
	if e = r.broadcast(selected, notice, ""); e != nil {
		return nil, e
	}
	selected.Members = append(selected.Members, key)
	log.Printf("%s pid=%d game=%d members=%d", map[bool]string{true: "create", false: "join"}[created], pid, selected.ID, len(selected.Members))
	return result, nil
}

func (r *registry) exchangeSetup(key string, raw []byte, matchExisting bool) ([]byte, error) {
	packet, e := decodePacket(raw)
	if e != nil {
		return nil, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(time.Now(), true)
	p := r.peers[key]
	if p != nil {
		p.Seen = time.Now()
		if bytes.Equal(raw, p.SetupRequest) {
			return append([]byte(nil), p.SetupReply...), nil
		}
	}
	if packet.Component() == 4 && packet.Command() == 20 && packet.MessageType() == 2 {
		if p != nil {
			return nil, errors.New("second setup in same matchmaking attempt")
		}
		return r.setupLocked(key, packet, raw, matchExisting)
	}
	if p == nil || p.GameID == 0 {
		return nil, nil
	}
	g := r.games[p.GameID]
	result := append([]byte(nil), raw...)
	if packet.MessageType() == 2 {
		gid, e := integerField(packet.Fields, "GID")
		if e != nil {
			return nil, e
		}
		if gid != g.ID {
			return nil, errors.New("foreign game notification")
		}
		switch packet.Command() {
		case 100:
			if key != g.Host {
				return nil, nil
			}
			state, e := integerField(packet.Fields, "GSTA")
			if e != nil {
				return nil, e
			}
			_ = setInteger(g.Data, "GSTA", state)
			if e = r.broadcast(g, raw, key); e != nil {
				return nil, e
			}
		case 116, 30:
			pid, e := integerField(packet.Fields, "PID")
			if e != nil {
				return nil, e
			}
			var member *peer
			for _, k := range g.Members {
				if mustInteger(r.peers[k].Player, "PID") == pid {
					member = r.peers[k]
					break
				}
			}
			if member == nil {
				return nil, errors.New("unknown mesh player")
			}
			if packet.Command() == 116 {
				state, e := integerField(packet.Fields, "STAT")
				if e != nil {
					return nil, e
				}
				_ = setInteger(member.Player, "STAT", state)
			}
			if e = r.broadcast(g, raw, key); e != nil {
				return nil, e
			}
		}
	}
	return result, nil
}

// exchange handles a public find-or-create setup. A create-only friends game
// uses exchangeSetup directly with matchExisting=false so it can never be
// selected by an unrelated public search.
func (r *registry) exchange(key string, raw []byte) ([]byte, error) {
	return r.exchangeSetup(key, raw, true)
}

// updateMesh records successful peer connectivity and emits the asynchronous
// player-join-completed notification expected after updateMeshConnection.
func (r *registry) updateMesh(key string, raw []byte) error {
	packet, err := decodePacket(raw)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.peers[key]
	if p == nil || p.GameID == 0 {
		return errors.New("mesh update before game setup")
	}
	g := r.games[p.GameID]
	if g == nil {
		return errors.New("mesh update for missing game")
	}
	gameID, err := integerField(packet.Fields, "GID")
	if err != nil || gameID != g.ID {
		return errors.New("mesh update for foreign game")
	}
	type meshTarget struct{ pid, state int64 }
	var meshTargets []meshTarget
	if targets, listErr := listField(packet.Fields, "TARG"); listErr == nil && targets.Kind == 3 {
		for _, item := range targets.Items {
			status, itemErr := fieldsFromItem(item)
			if itemErr != nil {
				return itemErr
			}
			pid, pidErr := integerField(status, "PID")
			state, stateErr := integerField(status, "STAT")
			if pidErr != nil || stateErr != nil {
				return errors.New("invalid mesh target")
			}
			meshTargets = append(meshTargets, meshTarget{pid: pid, state: state})
		}
	} else {
		// Rivals' ColdCli uses its older private schema: STAT is a root field
		// and TCG is an object id whose final element is the target player id.
		state, stateErr := integerField(packet.Fields, "STAT")
		targetField, targetErr := fieldAt(packet.Fields, "TCG")
		if stateErr != nil || targetErr != nil {
			return errors.New("invalid mesh target list")
		}
		objectID, ok := targetField.Value.(ObjectID)
		if !ok || len(objectID) == 0 {
			return errors.New("invalid mesh target connection group")
		}
		meshTargets = append(meshTargets, meshTarget{pid: objectID[len(objectID)-1], state: state})
	}
	for _, target := range meshTargets {
		pid, state := target.pid, target.state
		log.Printf("mesh update source=%s target=%d state=%d game=%d members=%d completed=%t", key, pid, state, g.ID, len(g.Members), g.Completed[pid])
		if state != 2 || g.Completed[pid] {
			continue
		}
		if err = r.completePlayerLocked(g, pid); err != nil {
			return err
		}
	}
	p.Seen = time.Now()
	return nil
}

func (r *registry) acknowledge(p *peer, after uint32) error {
	if after > p.Sequence {
		return errors.New("invalid notification cursor")
	}
	i := 0
	for i < len(p.Events) && p.Events[i].Sequence <= after {
		i++
	}
	p.Events = append([]queuedEvent(nil), p.Events[i:]...)
	if after > p.Delivered {
		p.Delivered = after
	}
	return nil
}
func (r *registry) poll(key string, after uint32) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(time.Now(), false)
	p := r.peers[key]
	if p == nil {
		return nil, nil
	}
	if e := r.acknowledge(p, after); e != nil {
		return nil, e
	}
	p.Seen = time.Now()
	var out bytes.Buffer
	for _, event := range p.Events {
		_ = binary.Write(&out, binary.LittleEndian, event.Sequence)
		_ = binary.Write(&out, binary.LittleEndian, uint32(len(event.Data)))
		out.Write(event.Data)
	}
	return out.Bytes(), nil
}
func (r *registry) ack(key string, after uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(time.Now(), false)
	p := r.peers[key]
	if p == nil {
		return nil
	}
	if e := r.acknowledge(p, after); e != nil {
		return e
	}
	p.Seen = time.Now()
	return nil
}

// drain returns and acknowledges all queued notifications for a directly
// connected Blaze client. The HTTP/ASI transport retains its cursor-based
// poll/ack path above.
func (r *registry) drain(key string) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.peers[key]
	if p == nil {
		return nil
	}
	p.Seen = time.Now()
	if len(p.Events) == 0 {
		return nil
	}
	result := make([][]byte, 0, len(p.Events))
	for _, event := range p.Events {
		result = append(result, append([]byte(nil), event.Data...))
		p.Delivered = event.Sequence
	}
	p.Events = nil
	return result
}

func (r *registry) gameID(key string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p := r.peers[key]; p != nil {
		return p.GameID
	}
	return 0
}
func (r *registry) leave(key string) { r.mu.Lock(); defer r.mu.Unlock(); r.removeLocked(key) }
