package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestNFS13NextPlaylistReturnsNativeEventSchema(t *testing.T) {
	// Query captured immediately before the title cleared context+0x461e.
	request := httptest.NewRequest(http.MethodGet,
		"http://192.168.4.199:48386/?getComponent=playlist&action=GetNextPlaylist&p0=100&posX=-680&posY=52&posZ=2244", nil)
	response := httptest.NewRecorder()
	(nfs13AutologHandler{}).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var result struct {
		Playlist struct {
			Name   string `json:"name"`
			Events []struct {
				ID int `json:"event_id"`
			} `json:"events"`
		} `json:"Playlist"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Playlist.Name == "" || len(result.Playlist.Events) == 0 || len(result.Playlist.Events) > 10 {
		t.Fatalf("playlist fails native name/event bounds: %+v", result.Playlist)
	}
	seen := make(map[int]bool)
	// Independent runtime evidence from capture 55804: this event resolved
	// to [317092848,27404]; all five former Survival IDs resolved to [0,0].
	verifiedAssets := map[int]bool{1113775: true}
	for _, event := range result.Playlist.Events {
		if !verifiedAssets[event.ID] {
			t.Fatalf("event %d has no verified native playlist asset", event.ID)
		}
		if event.ID <= 0 || seen[event.ID] {
			t.Fatalf("invalid or duplicate event: %d", event.ID)
		}
		seen[event.ID] = true
	}
	if bytes.Contains(response.Body.Bytes(), []byte("serverActive")) {
		t.Fatal("playlist request received RoadData manifest")
	}
	if response.Header().Get("Content-Length") != strconv.Itoa(response.Body.Len()) {
		t.Fatal("incorrect response length")
	}
}

func TestNFS13ManifestStillReturnsRoadData(t *testing.T) {
	response := httptest.NewRecorder()
	(nfs13AutologHandler{}).ServeHTTP(response,
		httptest.NewRequest(http.MethodGet, "http://localhost/nfs13/server-manifest", nil))
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), nfs13RoadDataManifest) {
		t.Fatal("manifest route changed")
	}
}

func TestNFS13ProfileLoaderObjects(t *testing.T) {
	for path, field := range map[string]string{
		"/nfs13/endpoint/18": "onlineProgression",
		"/nfs13/endpoint/19": "milestonePatches",
		"/nfs13/endpoint/20": "Patches",
	} {
		t.Run(field, func(t *testing.T) {
			response := httptest.NewRecorder()
			(nfs13AutologHandler{}).ServeHTTP(response,
				httptest.NewRequest(http.MethodGet, "http://localhost"+path+"?serviceName=GAMEPC", nil))
			var root map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &root); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusOK || string(root[field]) != "{}" {
				t.Fatalf("native parser requires empty object %s: %s", field, response.Body.String())
			}
			if _, manifest := root["serverActive"]; manifest {
				t.Fatal("received manifest instead of loader data")
			}
		})
	}
}
