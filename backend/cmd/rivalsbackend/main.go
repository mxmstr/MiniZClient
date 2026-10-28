package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type server struct {
	registry *registry
	token    string
}

var endpointPattern = regexp.MustCompile(`^/(exchange|poll|ack|leave)/([A-Za-z0-9-]{1,100})$`)

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Connection", "close")
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	provided := r.Header.Get("X-Rivals-Token")
	if len(provided) != len(s.token) || subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	match := endpointPattern.FindStringSubmatch(r.URL.Path)
	if match == nil {
		http.Error(w, "bad endpoint", http.StatusConflict)
		return
	}
	if r.ContentLength < 0 || r.ContentLength > maxBytes {
		http.Error(w, "bad body length", http.StatusConflict)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil || int64(len(body)) != r.ContentLength {
		http.Error(w, "short request", http.StatusConflict)
		return
	}
	action, key := match[1], match[2]
	var result []byte
	switch action {
	case "exchange":
		result, err = s.registry.exchange(key, body)
	case "poll":
		var after uint32
		after, err = parseAfter(r)
		if err == nil {
			result, err = s.registry.poll(key, after)
		}
	case "ack":
		var after uint32
		after, err = parseAfter(r)
		if err == nil {
			err = s.registry.ack(key, after)
		}
	case "leave":
		s.registry.leave(key)
	}
	if err != nil {
		log.Printf("request rejected action=%s key=%s: %v", action, key, err)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(result)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
}
func parseAfter(r *http.Request) (uint32, error) {
	text := r.URL.Query().Get("after")
	if text == "" {
		text = "0"
	}
	v, e := strconv.ParseUint(text, 10, 32)
	if e != nil {
		return 0, errors.New("invalid notification cursor")
	}
	return uint32(v), nil
}

func main() {
	profile := flag.String("profile", "rivals", "server profile: rivals, ds3-probe, or nfs13-probe")
	capture := flag.String("capture", "ds3_blaze_capture.jsonl", "JSONL request capture used by ds3-probe")
	listen := flag.String("listen", "", "HTTP listen address used by ZClient.Rivals.asi (defaults to advertised IPv4:48386)")
	blazeListen := flag.String("blaze-listen", "", "TLS/Blaze listen address used by NFS14 (defaults to advertised IPv4:4531)")
	disableBlaze := flag.Bool("disable-blaze", false, "disable the local TLS/Blaze replay service")
	redirectorListen := flag.String("redirector-listen", "", "TLS/Blaze redirector listen address used by CLoader (defaults to advertised IPv4:47127)")
	advertiseHost := flag.String("advertise-host", "", "non-loopback IPv4 address advertised to NFS14 (auto-detected when empty)")
	disableRedirector := flag.Bool("disable-redirector", false, "disable the local Blaze HTTPS redirector")
	token := flag.String("token", "", "shared ASCII token from ZClient.Rivals.ini")
	nfs13EAID := flag.String("nfs13-eaid", "player", "EAID assigned to the legacy NFS13 authentication token")
	nfs13Account := flag.Int64("nfs13-account-id", 100, "account/persona ID assigned to the legacy NFS13 authentication token")
	nfs13RewritePreAuth := flag.Bool("nfs13-rewrite-preauth", false, "rewrite captured pre-auth service metadata to the NFS13 request (experimental)")
	lan := flag.Bool("lan-addresses", false, "advertise each peer's internal endpoint as its external endpoint")
	hosted := flag.Bool("peer-hosted", false, "use direct peer-hosted topology instead of DirtyCast failover")
	ttl := flag.Duration("ttl", 90*time.Second, "inactive peer lifetime")
	flag.Parse()
	if *profile != "rivals" && *profile != "ds3-probe" && *profile != "nfs13-probe" {
		log.Fatal("-profile must be rivals, ds3-probe, or nfs13-probe")
	}
	if *advertiseHost == "" {
		var err error
		*advertiseHost, err = routedIPv4()
		if err != nil {
			log.Fatal(err)
		}
	}
	advertisedIP := net.ParseIP(*advertiseHost).To4()
	if advertisedIP == nil || advertisedIP[0] == 127 || advertisedIP.IsUnspecified() {
		log.Fatal("-advertise-host must be a non-loopback IPv4 address")
	}
	if *listen == "" {
		*listen = net.JoinHostPort(*advertiseHost, "48386")
	}
	if *blazeListen == "" {
		blazePort := "4531"
		blazeHost := *advertiseHost
		if *profile == "ds3-probe" {
			// Both captured ZClient sessions expose their plaintext DS3 proxy on
			// this fixed port and return "localhost" from the redirector. Listen
			// on every local interface so both literal loopback connections and
			// CLoader's LAN redirect reach the same service. Keeping the port exact
			// also preserves the redirector frame's encoded value.
			blazePort = "48482"
			blazeHost = "0.0.0.0"
		}
		*blazeListen = net.JoinHostPort(blazeHost, blazePort)
	}
	if *redirectorListen == "" {
		*redirectorListen = net.JoinHostPort(*advertiseHost, "47127")
	}
	if *profile == "rivals" && len(*token) < 16 {
		log.Fatal("-token must contain at least 16 printable ASCII characters")
	}
	if *profile == "nfs13-probe" &&
		((*nfs13EAID == "") != (*nfs13Account == 0) || *nfs13Account < 0) {
		log.Fatal("-nfs13-eaid and a positive -nfs13-account-id must be supplied together")
	}
	for _, c := range *token {
		if c < 33 || c > 126 {
			log.Fatal("-token must contain only printable ASCII without spaces")
		}
	}
	reg := newRegistry(*ttl, *lan, *hosted)
	handler := &server{registry: reg, token: *token}
	httpServer := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	var blazeListener net.Listener
	var redirectorListener net.Listener
	var blaze *blazeServer
	var nfs13AutologServer *http.Server
	if !*disableBlaze || !*disableRedirector {
		var err error
		blaze, err = newBlazeServer(*advertiseHost)
		if err != nil {
			log.Fatal(err)
		}
		blaze.nfs13 = *profile == "nfs13-probe"
		if *profile == "nfs13-probe" {
			blaze.legacyEAID = *nfs13EAID
			blaze.legacyAccount = *nfs13Account
			blaze.rewritePreAuth = *nfs13RewritePreAuth
			certificate, certificateErr := compactLegacyServiceCertificate(*advertiseHost)
			if certificateErr != nil {
				log.Fatal(certificateErr)
			}
			blaze.tlsConfig.Certificates = []tls.Certificate{certificate}
			log.Printf("NFS13 compact SSL3 leaf configured (DER bytes=%d)",
				len(certificate.Certificate[0]))
		}
		blaze.registry = reg
		if !*disableBlaze && *profile != "nfs13-probe" {
			blazeListener, err = net.Listen("tcp", *blazeListen)
			if err != nil {
				log.Fatalf("listen for TLS/Blaze on %s: %v", *blazeListen, err)
			}
		}
		if !*disableRedirector && *profile == "rivals" {
			_, _, splitErr := net.SplitHostPort(*blazeListen)
			if splitErr != nil {
				log.Fatalf("invalid -blaze-listen address: %v", splitErr)
			}
			redirectorListener, err = net.Listen("tcp", *redirectorListen)
			if err != nil {
				log.Fatalf("listen for Blaze redirector on %s: %v", *redirectorListen, err)
			}
		}
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			reg.mu.Lock()
			reg.expireLocked(time.Now(), true)
			reg.mu.Unlock()
		}
	}()
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	serviceContext, cancelServices := context.WithCancel(context.Background())
	defer cancelServices()
	serverErrors := make(chan error, 4)
	if blazeListener != nil {
		if *profile == "ds3-probe" {
			go func() { serverErrors <- serveDS3BlazeReplay(blazeListener, *capture) }()
			log.Printf("DS3 plaintext Blaze replay listening on %s", *blazeListen)
		} else {
			go func() { serverErrors <- blaze.serve(blazeListener) }()
			log.Printf("Rivals TLS/Blaze replay listening on %s", *blazeListen)
		}
	}
	if redirectorListener != nil {
		_, blazePort, _ := net.SplitHostPort(*blazeListen)
		redirectorConfig := redirectorTLSConfig(blaze.tlsConfig)
		if *profile == "ds3-probe" {
			redirectorConfig = ds3RedirectorTLSConfig(blaze.tlsConfig)
		}
		go func() {
			serverErrors <- serveBlazeRedirector(redirectorListener, redirectorConfig, *advertiseHost, blazePort)
		}()
		log.Printf("%s TLS/Blaze redirector listening on %s", *profile, *redirectorListen)
	}
	if !*disableRedirector && (*profile == "ds3-probe" || *profile == "nfs13-probe") {
		_, blazePortText, _ := net.SplitHostPort(*blazeListen)
		blazePortValue, parseErr := strconv.ParseUint(blazePortText, 10, 16)
		if parseErr != nil || blazePortValue == 0 {
			log.Fatalf("invalid -blaze-listen port %q", blazePortText)
		}
		secureBlaze := *profile == "nfs13-probe"
		go func() {
			redirectorCapture := strings.TrimSuffix(*capture, filepath.Ext(*capture)) + "_redirector" + filepath.Ext(*capture)
			serverErrors <- serveSSL3Redirector(serviceContext, *redirectorListen,
				blaze.tlsConfig.Certificates[0], *advertiseHost, uint16(blazePortValue),
				redirectorCapture, secureBlaze)
		}()
	}
	if !*disableBlaze && *profile == "nfs13-probe" {
		nfs13AutologServer = newNFS13AutologServer()
		go func() { serverErrors <- nfs13AutologServer.ListenAndServe() }()
		go func() {
			serverErrors <- serveSSL3BlazeReplay(serviceContext, *blazeListen,
				blaze.tlsConfig.Certificates[0], blaze)
		}()
		go func() {
			serverErrors <- serveNFS13AuxiliaryProbe(serviceContext,
				nfs13AuxiliaryProbeAddress, blaze)
		}()
		log.Printf("NFS13 auxiliary protocol probe listening on %s", nfs13AuxiliaryProbeAddress)
		log.Printf("NFS13 Autolog manifest service listening on %s (advertised as %s)",
			nfs13AutologServer.Addr, nfs13AutologBaseURL(*advertiseHost))
	}
	if *profile == "rivals" {
		log.Printf("Rivals Go coordinator listening on %s (advertise_host=%s lan_addresses=%t peer_hosted=%t)", *listen, *advertiseHost, *lan, *hosted)
		go func() { serverErrors <- httpServer.ListenAndServe() }()
	}
	select {
	case <-done:
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Printf("server stopped: %v", err)
		}
	}
	cancelServices()
	_ = httpServer.Close()
	if nfs13AutologServer != nil {
		_ = nfs13AutologServer.Close()
	}
	if blazeListener != nil {
		_ = blazeListener.Close()
	}
	if redirectorListener != nil {
		_ = redirectorListener.Close()
	}
}

func routedIPv4() (string, error) {
	connection, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return "", fmt.Errorf("select non-loopback service address: %w; pass -advertise-host", err)
	}
	defer connection.Close()
	address, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok || address.IP.To4() == nil || address.IP.IsLoopback() || address.IP.IsUnspecified() {
		return "", errors.New("could not select a non-loopback IPv4 address; pass -advertise-host")
	}
	return address.IP.String(), nil
}

func usage() {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(`
Run beside ZClient.exe and use the same token in ZClient.Rivals.ini:
  go run ./cmd/rivalsbackend -token YOUR_SHARED_TOKEN

The NFS14-facing services listen on all interfaces and advertise the routed LAN IPv4.
`))
}
