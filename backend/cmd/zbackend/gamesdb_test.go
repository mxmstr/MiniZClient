package main

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"testing"
)

func catalogRequest(command uint32, args ...uint32) []byte {
	p := appendU32(make([]byte, 5), command)
	for _, arg := range args {
		p = appendU32(p, arg)
	}
	p[0] = 18
	binary.LittleEndian.PutUint32(p[1:], uint32(len(p)-5))
	return p
}

func TestFrozenCatalogMatchesOnlineState(t *testing.T) {
	want, _ := hex.DecodeString("1210000000ac7766d80007e016000003f7000011b3")
	p, _ := gamesDBResponse(catalogRequest(0xac7766d8))
	if !bytes.Equal(p, want) {
		t.Fatalf("state %x", p)
	}
	if fmt.Sprintf("%x", sha256.Sum256(gamesDBSnapshot)) != "3641e9505ba7549512621648ec3289e422526021cf7e6b57b0d6320c9000469b" {
		t.Fatal("snapshot changed without updating provenance")
	}
	for _, o := range localCatalog.objects {
		r, err := zlib.NewReader(bytes.NewReader(o.compressed))
		if err != nil {
			t.Fatalf("object %d: %v", o.id, err)
		}
		n, err := io.Copy(io.Discard, io.LimitReader(r, 16<<20))
		r.Close()
		if err != nil || n == 0 || n == 16<<20 {
			t.Fatalf("object %d invalid: %v", o.id, err)
		}
	}
}

func TestFrozenCatalogFullAndDeltaIndex(t *testing.T) {
	for _, cursor := range []uint32{0, 0x11b1, 0x11b3} {
		p, _ := gamesDBResponse(catalogRequest(0x08775d76, cursor))
		if len(p) < 21 || !bytes.Equal(p[9:21], localCatalog.headers) {
			t.Fatal("inconsistent index state")
		}
		seen := map[uint32]bool{}
		for rest := p[21:]; len(rest) > 0; rest = rest[8:] {
			id, change := binary.BigEndian.Uint32(rest), binary.BigEndian.Uint32(rest[4:])
			if seen[id] || localCatalog.byID[id].change != change || change <= cursor {
				t.Fatal("invalid index entry")
			}
			seen[id] = true
		}
		for _, o := range localCatalog.objects {
			if seen[o.id] != (o.change > cursor) {
				t.Fatal("missing index entry")
			}
		}
	}
}

func TestFrozenCatalogObjectsMatchCapturedBatch(t *testing.T) {
	// Seven hashes come from online packet 18. Object 0x343 advanced from
	// change 0x11b1 to 0x11b3 in the newer matching CDN snapshot.
	ids := []uint32{0x301, 0x32b, 0x343, 0x37d, 0x38f, 0x3c5, 0x3f1, 0x3f8}
	hashes := []string{
		"4c80856fb8c5a7318426b3409456a31e82b43a42878fae8fd58a388c118a74b0",
		"a93333abda429917a4d85cb34eda7612113eae0ffeceed111b9ba12fb1266110",
		"800dfe8d24766d350e05f418d30235233833538398f3a846caae12df2349ca82",
		"7a752c097616c4e09c690589173eefbef98affafba179514ee4d91b61b381c95",
		"9d4ab682e41601ac77b8c4c47697ac6e4c9685e364fc73ff2d097044ce494f17",
		"9f63833b9a0555abf73cbbf24a7bffb7faf6d1d0a183ca9c42111b1027afd81b",
		"6707c48194eb64514a99ad0a04cec0a731e2303847dd0e74b725e15d3967687d",
		"6aab5ad6ae15b93ad8958966fde63fc5132f4c41486782b3ab455794fdcca618",
	}
	p, _ := gamesDBResponse(catalogRequest(0xba50633d, ids...))
	if len(p) != 372395 {
		t.Fatalf("batch bytes=%d", len(p))
	}
	rest := p[9:]
	for i, id := range ids {
		if len(rest) < 13 || binary.BigEndian.Uint32(rest) != id || rest[4] != 1 {
			t.Fatal("bad object envelope")
		}
		size := int(binary.BigEndian.Uint32(rest[9:]))
		if len(rest) < 13+size {
			t.Fatal("truncated object")
		}
		if fmt.Sprintf("%x", sha256.Sum256(rest[13:13+size])) != hashes[i] {
			t.Fatalf("captured object %x differs", id)
		}
		rest = rest[13+size:]
	}
	if len(rest) != 0 {
		t.Fatal("trailing objects")
	}
}

func TestFrozenCatalogBootstrapAllObjects(t *testing.T) {
	// Walk the entire index in the client's observed eight-object batches.
	for start := 0; start < len(localCatalog.objects); start += 8 {
		var ids []uint32
		for i := start; i < start+8 && i < len(localCatalog.objects); i++ {
			ids = append(ids, localCatalog.objects[i].id)
		}
		p, why := gamesDBResponse(catalogRequest(0xba50633d, ids...))
		if len(p) < 9 || len(p) > maxQueuedBytes {
			t.Fatalf("bootstrap batch %d: %s", start, why)
		}
	}
	unknown, _ := gamesDBResponse(catalogRequest(0xba50633d, 0xffffffff))
	if len(unknown) != 14 || unknown[13] != 0 {
		t.Fatal("unknown game must be absent")
	}
	for _, request := range [][]byte{nil, catalogRequest(0xffffffff), catalogRequest(0x08775d76), catalogRequest(0xba50633d)} {
		if p, _ := gamesDBResponse(request); p != nil {
			t.Fatal("invalid request accepted")
		}
	}
	if _, err := parseCatalog(gamesDBSnapshot[:len(gamesDBSnapshot)-1]); err == nil {
		t.Fatal("truncated snapshot accepted")
	}
}

func TestFrozenCatalogEncryptedTransport(t *testing.T) {
	store, err := openAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := loginPresenceClient(t, newBackend(store, ""), "CatalogUser")
	for _, request := range [][]byte{catalogRequest(0xac7766d8), catalogRequest(0x08775d76, 0), catalogRequest(0xba50633d, 0x301, 0x32b, 0x343, 0x37d, 0x38f, 0x3c5, 0x3f1, 0x3f8), {0, 0, 0, 0, 0}} {
		want, _ := gamesDBResponse(request)
		if request[0] == 0 {
			want = request
		}
		got, err := c.exchange(request)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("encrypted catalog exchange type=%d: %v", request[0], err)
		}
	}
}
