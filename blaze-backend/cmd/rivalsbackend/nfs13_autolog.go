package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

const nfs13AutologPort = 48386

var nfs13RoadDataManifest = []byte(`{
  "serverActive": true,
  "allow": {
    "postPhotos": false,
    "uploadFrequency": 300.0,
    "uploadSessionFrequency": 300.0,
    "HTTPTimout": 10000,
    "HTTPRetry": 1
  },
  "bundles": {}
}`)

// FUN_006e0410 reads Playlist, and FUN_006df4c0 resolves each event_id
// against the installed game's event assets. Capture 55804 resolved 1113775
// to a real asset during online startup. The previously used Survival IDs
// all resolved to null and produced accepted_events=0. Use one verified
// asset while the full multiplayer Speedlist contract is being recovered.
// Keep the list below its native ten-event capacity. Missing/empty playlists
// make FUN_006e7bc0 clear Autolog's connected flag and abandon the session.
var nfs13LANPlaylist = []byte(`{
  "Playlist": {
    "name": "LAN Speedlist",
    "events": [
      {"event_id": 1113775}
    ]
  }
}`)

func nfs13AutologBaseURL(advertiseHost string) string {
	return "http://" + net.JoinHostPort(advertiseHost, strconv.Itoa(nfs13AutologPort))
}

type nfs13AutologHandler struct{}

func (nfs13AutologHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	log.Printf("NFS13 Autolog request method=%s host=%q path=%q query=%q bytes=%d user_agent=%q",
		r.Method, r.Host, r.URL.Path, r.URL.RawQuery, len(body), r.UserAgent())

	payload := nfs13RoadDataManifest
	// Native parsers 0068aab0 and 00699130 require objects, not arrays.
	// Empty objects represent no server progression records or patch entries.
	switch r.URL.Path {
	case "/nfs13/endpoint/18":
		payload = []byte(`{"onlineProgression":{}}`)
		log.Printf("NFS13 Autolog reply route=onlineProgression records=0")
	case "/nfs13/endpoint/20":
		payload = []byte(`{"Patches":{}}`)
		log.Printf("NFS13 Autolog reply route=Patches records=0")
	case "/nfs13/endpoint/19":
		// FUN_006f25b0 accepts an empty object; missing fields fail state 7.
		payload = []byte(`{"milestonePatches":{}}`)
		log.Printf("NFS13 Autolog reply route=milestonePatches records=0")
	}
	query := r.URL.Query()
	if query.Get("getComponent") == "playlist" && query.Get("action") == "GetNextPlaylist" {
		payload = nfs13LANPlaylist
		log.Printf("NFS13 Autolog reply route=playlist/GetNextPlaylist events=1 event_id=1113775")
	}
	// Unknown routes retain the discovery response until their contracts are
	// recovered. A manifest must not substitute for a known playlist request:
	// valid JSON alone does not satisfy the title's playlist parser.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func newNFS13AutologServer() *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", nfs13AutologPort),
		Handler:           nfs13AutologHandler{},
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}
