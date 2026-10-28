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

	// The first Autolog transaction is the RoadData server manifest.  Return a
	// valid, deliberately minimal document for every local Autolog route while
	// discovery is in progress: this makes the request observable and keeps an
	// unknown endpoint from receiving an HTML 404 page that the game would try
	// to parse as JSON.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Length", strconv.Itoa(len(nfs13RoadDataManifest)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(nfs13RoadDataManifest)
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
