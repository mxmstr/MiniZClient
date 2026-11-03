package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const maxBytes = 1 << 20
const maxItems = 8192
const maxDepth = 32

type Field struct {
	Tag   string
	Kind  byte
	Value any
}

type List struct {
	Kind  byte
	Items []any
}

type Pair struct{ Key, Value any }
type MapValue struct {
	KeyKind, ValueKind byte
	Pairs              []Pair
}
type Union struct {
	Index byte
	Field *Field
}
type Variable struct {
	Present bool
	TypeID  int64
	Field   *Field
}
type ObjectID []int64
type LegacyAddress struct{ Fields []Field }

type reader struct {
	data  []byte
	pos   int
	items int
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.data) {
		return nil, fmt.Errorf("truncated value at %d", r.pos)
	}
	v := r.data[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}

func (r *reader) integer() (int64, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	value, negative, shift := uint64(b[0]&63), b[0]&64 != 0, uint(6)
	current := b[0]
	for current&128 != 0 {
		if shift >= 64 {
			return 0, errors.New("varint exceeds 64 bits")
		}
		b, err = r.take(1)
		if err != nil {
			return 0, err
		}
		current = b[0]
		value |= uint64(current&127) << shift
		shift += 7
	}
	if negative {
		if value > 1<<63 {
			return 0, errors.New("negative varint overflow")
		}
		if value == 1<<63 {
			return -1 << 63, nil
		}
		return -int64(value), nil
	}
	if value > 1<<63-1 {
		return 0, errors.New("integer exceeds signed 64-bit range")
	}
	return int64(value), nil
}

func (r *reader) count() (int, error) {
	v, err := r.integer()
	if err != nil {
		return 0, err
	}
	if v < 0 || v > maxItems {
		return 0, errors.New("collection exceeds item limit")
	}
	return int(v), nil
}

func decodeTag(raw []byte) string {
	v := uint32(raw[0])<<16 | uint32(raw[1])<<8 | uint32(raw[2])
	out := make([]byte, 0, 4)
	for _, shift := range []uint{18, 12, 6, 0} {
		c := byte((v>>shift)&63) + 32
		if c != ' ' {
			out = append(out, c)
		}
	}
	return string(out)
}

func (r *reader) fields(nested bool, depth int) ([]Field, error) {
	var out []Field
	for r.pos < len(r.data) {
		if r.data[r.pos] == 0 {
			if !nested {
				return nil, errors.New("unexpected root terminator")
			}
			r.pos++
			return out, nil
		}
		f, err := r.field(depth)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if nested {
		return nil, errors.New("unterminated struct")
	}
	return out, nil
}

func (r *reader) field(depth int) (Field, error) {
	tag, err := r.take(3)
	if err != nil {
		return Field{}, err
	}
	kind, err := r.take(1)
	if err != nil {
		return Field{}, err
	}
	name := decodeTag(tag)
	if name == "" {
		return Field{}, errors.New("empty field tag")
	}
	v, err := r.value(kind[0], depth+1, name)
	return Field{Tag: name, Kind: kind[0], Value: v}, err
}

func (r *reader) value(kind byte, depth int, tag string) (any, error) {
	r.items++
	if r.items > maxItems || depth > maxDepth {
		return nil, errors.New("TDF complexity limit exceeded")
	}
	switch kind {
	case 0, 11:
		return r.integer()
	case 1, 2:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		v, err := r.take(n)
		if err != nil {
			return nil, err
		}
		v = append([]byte(nil), v...)
		if kind == 1 {
			if len(v) == 0 || v[len(v)-1] != 0 {
				return nil, errors.New("string lacks NUL terminator")
			}
			v = v[:len(v)-1]
		}
		return v, nil
	case 3:
		return r.fields(true, depth)
	case 4:
		sub, err := r.take(1)
		if err != nil {
			return nil, err
		}
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		list := List{Kind: sub[0], Items: make([]any, 0, n)}
		for i := 0; i < n; i++ {
			if tag == "HNET" && sub[0] == 3 && r.pos < len(r.data) && r.data[r.pos] == 2 {
				r.pos++
				fields, e := r.fields(true, depth+1)
				if e != nil {
					return nil, e
				}
				list.Items = append(list.Items, LegacyAddress{Fields: fields})
			} else {
				v, e := r.value(sub[0], depth+1, tag)
				if e != nil {
					return nil, e
				}
				list.Items = append(list.Items, v)
			}
		}
		return list, nil
	case 5:
		types, err := r.take(2)
		if err != nil {
			return nil, err
		}
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		m := MapValue{KeyKind: types[0], ValueKind: types[1], Pairs: make([]Pair, 0, n)}
		for i := 0; i < n; i++ {
			k, e := r.value(types[0], depth+1, "")
			if e != nil {
				return nil, e
			}
			v, e := r.value(types[1], depth+1, "")
			if e != nil {
				return nil, e
			}
			m.Pairs = append(m.Pairs, Pair{Key: k, Value: v})
		}
		return m, nil
	case 6:
		idx, err := r.take(1)
		if err != nil {
			return nil, err
		}
		u := Union{Index: idx[0]}
		if u.Index != 127 {
			f, e := r.field(depth)
			if e != nil {
				return nil, e
			}
			u.Field = &f
		}
		return u, nil
	case 7:
		present, err := r.take(1)
		if err != nil {
			return nil, err
		}
		if present[0] == 0 {
			return Variable{}, nil
		}
		if present[0] != 1 {
			return nil, errors.New("invalid variable presence flag")
		}
		id, err := r.integer()
		if err != nil {
			return nil, err
		}
		f, err := r.field(depth)
		if err != nil {
			return nil, err
		}
		end, err := r.take(1)
		if err != nil || end[0] != 0 {
			return nil, errors.New("variable lacks terminator")
		}
		return Variable{Present: true, TypeID: id, Field: &f}, nil
	case 8, 9:
		n := 2
		if kind == 9 {
			n = 3
		}
		ids := make(ObjectID, n)
		for i := range ids {
			v, e := r.integer()
			if e != nil {
				return nil, e
			}
			ids[i] = v
		}
		return ids, nil
	case 10:
		v, err := r.take(4)
		return append([]byte(nil), v...), err
	default:
		return nil, fmt.Errorf("unsupported TDF type %#x", kind)
	}
}

func varint(value int64) []byte {
	negative := value < 0
	var v uint64
	if negative {
		v = uint64(-(value + 1)) + 1
	} else {
		v = uint64(value)
	}
	out := []byte{byte(v & 63)}
	if negative {
		out[0] |= 64
	}
	v >>= 6
	for v != 0 {
		out[len(out)-1] |= 128
		out = append(out, byte(v&127))
		v >>= 7
	}
	return out
}

func encodeValue(kind byte, value any, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, errors.New("TDF depth limit exceeded")
	}
	var out bytes.Buffer
	switch kind {
	case 0, 11:
		v, ok := value.(int64)
		if !ok {
			return nil, fmt.Errorf("integer value has type %T", value)
		}
		out.Write(varint(v))
	case 1, 2:
		v, ok := value.([]byte)
		if !ok {
			return nil, fmt.Errorf("byte value has type %T", value)
		}
		n := len(v)
		if kind == 1 {
			n++
		}
		out.Write(varint(int64(n)))
		out.Write(v)
		if kind == 1 {
			out.WriteByte(0)
		}
	case 3:
		switch v := value.(type) {
		case []Field:
			b, e := encodeFields(v, depth+1)
			if e != nil {
				return nil, e
			}
			out.Write(b)
			out.WriteByte(0)
		case LegacyAddress:
			out.WriteByte(2)
			b, e := encodeFields(v.Fields, depth+1)
			if e != nil {
				return nil, e
			}
			out.Write(b)
			out.WriteByte(0)
		default:
			return nil, fmt.Errorf("struct value has type %T", value)
		}
	case 4:
		v, ok := value.(List)
		if !ok || len(v.Items) > maxItems {
			return nil, errors.New("invalid list")
		}
		out.WriteByte(v.Kind)
		out.Write(varint(int64(len(v.Items))))
		for _, item := range v.Items {
			b, e := encodeValue(v.Kind, item, depth+1)
			if e != nil {
				return nil, e
			}
			out.Write(b)
		}
	case 5:
		v, ok := value.(MapValue)
		if !ok || len(v.Pairs) > maxItems {
			return nil, errors.New("invalid map")
		}
		out.WriteByte(v.KeyKind)
		out.WriteByte(v.ValueKind)
		out.Write(varint(int64(len(v.Pairs))))
		for _, p := range v.Pairs {
			for _, x := range []struct {
				k byte
				v any
			}{{v.KeyKind, p.Key}, {v.ValueKind, p.Value}} {
				b, e := encodeValue(x.k, x.v, depth+1)
				if e != nil {
					return nil, e
				}
				out.Write(b)
			}
		}
	case 6:
		v, ok := value.(Union)
		if !ok || (v.Index == 127) != (v.Field == nil) {
			return nil, errors.New("invalid union")
		}
		out.WriteByte(v.Index)
		if v.Field != nil {
			b, e := encodeField(*v.Field, depth+1)
			if e != nil {
				return nil, e
			}
			out.Write(b)
		}
	case 7:
		v, ok := value.(Variable)
		if !ok {
			return nil, errors.New("invalid variable")
		}
		if !v.Present {
			out.WriteByte(0)
		} else {
			if v.Field == nil {
				return nil, errors.New("missing variable field")
			}
			out.WriteByte(1)
			out.Write(varint(v.TypeID))
			b, e := encodeField(*v.Field, depth+1)
			if e != nil {
				return nil, e
			}
			out.Write(b)
			out.WriteByte(0)
		}
	case 8, 9:
		v, ok := value.(ObjectID)
		expected := 2
		if kind == 9 {
			expected = 3
		}
		if !ok || len(v) != expected {
			return nil, errors.New("invalid object identifier")
		}
		for _, x := range v {
			out.Write(varint(x))
		}
	case 10:
		v, ok := value.([]byte)
		if !ok || len(v) != 4 {
			return nil, errors.New("invalid float payload")
		}
		out.Write(v)
	default:
		return nil, fmt.Errorf("unsupported TDF type %#x", kind)
	}
	return out.Bytes(), nil
}

func encodeTag(tag string) ([]byte, error) {
	if len(tag) < 1 || len(tag) > 4 {
		return nil, errors.New("invalid TDF tag")
	}
	var v uint32
	for i := 0; i < 4; i++ {
		c := byte(' ')
		if i < len(tag) {
			c = tag[i]
		}
		if c < 33 && i < len(tag) || c > 95 {
			return nil, errors.New("invalid TDF tag")
		}
		v = (v << 6) | uint32(c-32)
	}
	return []byte{byte(v >> 16), byte(v >> 8), byte(v)}, nil
}
func encodeField(f Field, depth int) ([]byte, error) {
	tag, e := encodeTag(f.Tag)
	if e != nil {
		return nil, e
	}
	v, e := encodeValue(f.Kind, f.Value, depth)
	if e != nil {
		return nil, e
	}
	return append(append(tag, f.Kind), v...), nil
}
func encodeFields(fields []Field, depth int) ([]byte, error) {
	if len(fields) > maxItems {
		return nil, errors.New("too many fields")
	}
	var out bytes.Buffer
	for _, f := range fields {
		b, e := encodeField(f, depth)
		if e != nil {
			return nil, e
		}
		out.Write(b)
	}
	if out.Len() > maxBytes {
		return nil, errors.New("TDF exceeds byte limit")
	}
	return out.Bytes(), nil
}

type Packet struct {
	Header []byte
	Fields []Field
}

func (p Packet) Component() uint16 { return binary.BigEndian.Uint16(p.Header[2:4]) }
func (p Packet) Command() uint16   { return binary.BigEndian.Uint16(p.Header[4:6]) }
func (p Packet) MessageType() byte { return p.Header[8] >> 4 }
func decodePacket(data []byte) (Packet, error) {
	if len(data) < 12 || len(data) > maxBytes {
		return Packet{}, errors.New("invalid frame size")
	}
	flags := data[9] >> 4
	size, hsize := int(binary.BigEndian.Uint16(data[:2])), 12
	if flags&1 != 0 {
		if len(data) < 14 {
			return Packet{}, errors.New("truncated jumbo header")
		}
		size |= int(binary.BigEndian.Uint16(data[12:14])) << 16
		hsize += 2
	}
	if flags&2 != 0 {
		if flags&8 != 0 {
			hsize += 8
		} else {
			hsize += 4
		}
	} else if flags&8 != 0 {
		return Packet{}, errors.New("jumbo context without context flag")
	}
	if len(data) != hsize+size {
		return Packet{}, errors.New("frame length mismatch")
	}
	r := reader{data: data[hsize:]}
	fields, e := r.fields(false, 0)
	if e != nil {
		return Packet{}, e
	}
	return Packet{Header: append([]byte(nil), data[:hsize]...), Fields: fields}, nil
}
func (p Packet) Encode() ([]byte, error) {
	body, e := encodeFields(p.Fields, 0)
	if e != nil {
		return nil, e
	}
	h := append([]byte(nil), p.Header...)
	if len(body) > 65535 && h[9]&0x10 == 0 {
		h[9] |= 0x10
		h = append(h[:12], append([]byte{0, 0}, h[12:]...)...)
	}
	binary.BigEndian.PutUint16(h[:2], uint16(len(body)))
	if h[9]&0x10 != 0 {
		binary.BigEndian.PutUint16(h[12:14], uint16(len(body)>>16))
	}
	out := append(h, body...)
	if len(out) > maxBytes {
		return nil, errors.New("frame exceeds byte limit")
	}
	return out, nil
}
func clonePacket(p Packet) (Packet, error) {
	raw, e := p.Encode()
	if e != nil {
		return Packet{}, e
	}
	return decodePacket(raw)
}
func fieldAt(fields []Field, tag string, kind ...byte) (*Field, error) {
	var found *Field
	for i := range fields {
		if fields[i].Tag == tag {
			if found != nil {
				return nil, fmt.Errorf("duplicate %s", tag)
			}
			found = &fields[i]
		}
	}
	if found == nil || len(kind) > 0 && found.Kind != kind[0] {
		return nil, fmt.Errorf("missing or mistyped %s", tag)
	}
	return found, nil
}
func integerField(fields []Field, tag string) (int64, error) {
	f, e := fieldAt(fields, tag, 0)
	if e != nil {
		return 0, e
	}
	v, ok := f.Value.(int64)
	if !ok {
		return 0, fmt.Errorf("bad integer %s", tag)
	}
	return v, nil
}
func structField(fields []Field, tag string) ([]Field, error) {
	f, e := fieldAt(fields, tag, 3)
	if e != nil {
		return nil, e
	}
	v, ok := f.Value.([]Field)
	if !ok {
		return nil, fmt.Errorf("bad struct %s", tag)
	}
	return v, nil
}
func setInteger(fields []Field, tag string, value int64) error {
	f, e := fieldAt(fields, tag, 0)
	if e != nil {
		return e
	}
	f.Value = value
	return nil
}
