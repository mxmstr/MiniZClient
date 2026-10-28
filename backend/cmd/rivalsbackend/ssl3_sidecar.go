package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const sidecarWriteMarker = "[DS3SSL] SSL_write completed bytes="

func relaySidecarDiagnostics(reader io.Reader, writes chan<- int) {
	defer close(writes)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintln(os.Stderr, line)
		if !strings.HasPrefix(line, sidecarWriteMarker) {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, sidecarWriteMarker)))
		if err == nil {
			writes <- count
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("DS3 SSL3 sidecar diagnostics failed: %v", err)
	}
}

func waitSidecarWrite(ctx context.Context, writes <-chan int, expected int) error {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("timed out waiting for SSL_write(%d)", expected)
		case count, ok := <-writes:
			if !ok {
				return fmt.Errorf("SSL3 sidecar exited before SSL_write(%d)", expected)
			}
			if count == expected {
				return nil
			}
		}
	}
}

func validateSSL3OpenSSL(path string) (string, error) {
	command := exec.Command(path, "version")
	command.Env = append(os.Environ(), "OPENSSL_CONF="+os.DevNull)
	output, err := command.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		return text, fmt.Errorf("run %s version: %w", path, err)
	}
	// OpenSSL 3 deliberately has SSL3 removed even when its command-line parser
	// accepts an SSLv3 minimum.  The private 1.0.2u build is configured with
	// enable-ssl3 and enable-ssl3-method and is the only supported sidecar.
	for _, line := range strings.Split(text, "\n") {
		version := strings.TrimSpace(line)
		if strings.HasPrefix(version, "OpenSSL 1.0.2") {
			image, readErr := os.ReadFile(path)
			if readErr != nil {
				return text, fmt.Errorf("read SSL3 runtime: %w", readErr)
			}
			// Stock s_server on Windows only polls console input with _kbhit().
			// The backend uses an anonymous stdin pipe, so it specifically needs
			// our redirected-stdin build.  Checking its diagnostic marker keeps a
			// stale stock 1.0.2 binary from silently completing the handshake but
			// never sending the Blaze response.
			if !bytes.Contains(image, []byte("[DS3SSL] sidecar pipe ready")) {
				return text, errors.New("OpenSSL 1.0.2 runtime is missing the DS3 redirected-stdin patch")
			}
			return version, nil
		}
	}
	return text, fmt.Errorf("%s is not the bundled SSL3-capable OpenSSL 1.0.2 runtime", text)
}

func findOpenSSL() (string, string, error) {
	var candidates []string
	if override := strings.TrimSpace(os.Getenv("ZCLIENT_SSL3_OPENSSL")); override != "" {
		candidates = append(candidates, override)
	}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates,
			filepath.Join(filepath.Dir(executable), "openssl-ssl3", "openssl-ds3-pipe.exe"),
			filepath.Join(filepath.Dir(executable), "openssl-ssl3", "openssl-ds3.exe"))
	}
	if workingDirectory, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(workingDirectory, "build", "openssl-ssl3", "openssl-ds3-pipe.exe"),
			filepath.Join(workingDirectory, "build", "openssl-ssl3", "openssl-ds3.exe"))
	}

	var rejected []string
	for _, path := range candidates {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		version, err := validateSSL3OpenSSL(path)
		if err == nil {
			return path, version, nil
		}
		rejected = append(rejected, fmt.Sprintf("%s (%v)", path, err))
	}
	if len(rejected) != 0 {
		return "", "", fmt.Errorf("no usable SSL3 runtime: %s", strings.Join(rejected, "; "))
	}
	return "", "", errors.New("bundled patched SSL3 runtime was not found; expected openssl-ssl3\\openssl-ds3-pipe.exe beside ds3-backend.exe (or set ZCLIENT_SSL3_OPENSSL)")
}

func writeSidecarCertificate(directory string, certificate tls.Certificate) (string, string, string, error) {
	if len(certificate.Certificate) == 0 {
		return "", "", "", errors.New("TLS certificate has no leaf")
	}
	key, ok := certificate.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return "", "", "", fmt.Errorf("unsupported TLS private key %T", certificate.PrivateKey)
	}
	certPath := filepath.Join(directory, "leaf.pem")
	keyPath := filepath.Join(directory, "leaf-key.pem")
	chainPath := ""
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", "", err
	}
	if len(certificate.Certificate) > 1 {
		chainPath = filepath.Join(directory, "chain.pem")
		var chainPEM []byte
		for _, der := range certificate.Certificate[1:] {
			chainPEM = append(chainPEM,
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		if err := os.WriteFile(chainPath, chainPEM, 0o600); err != nil {
			return "", "", "", err
		}
	}
	return certPath, keyPath, chainPath, nil
}

// serveSSL3Redirector uses OpenSSL only as the obsolete SSL3 record/handshake
// layer. Blaze parsing and response construction remain in this process.
func serveSSL3Redirector(ctx context.Context, address string,
	certificate tls.Certificate, advertiseHost string, blazePort uint16,
	capturePath string, secureBlaze bool) error {
	openssl, opensslVersion, err := findOpenSSL()
	if err != nil {
		return err
	}
	_, listenPort, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid SSL3 redirector address %q: %w", address, err)
	}
	log.Printf("DS3 SSL3 sidecar runtime verified: %s (%s)", opensslVersion, openssl)
	directory, err := os.MkdirTemp("", "zclient-ds3-ssl3-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	certPath, keyPath, chainPath, err := writeSidecarCertificate(directory, certificate)
	if err != nil {
		return err
	}
	captureFile, err := os.OpenFile(capturePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer captureFile.Close()
	capture := &probeCapture{encoder: json.NewEncoder(captureFile)}

	for ctx.Err() == nil {
		arguments := []string{"s_server", "-accept", listenPort,
			"-cert", certPath, "-key", keyPath}
		if chainPath != "" {
			arguments = append(arguments, "-cert_chain", chainPath)
		}
		arguments = append(arguments,
			"-quiet", "-state", "-naccept", "1", "-ssl3", "-cipher", "AES256-SHA",
			// SSL_OP_ALL includes SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS in
			// OpenSSL 1.0.2. DirtySSL does not discard OpenSSL's CBC empty
			// fragment and exposes it as garbage plaintext, while ZClient's
			// server sends the prefix record without that mitigation record.
			"-bugs")
		command := exec.CommandContext(ctx, openssl, arguments...)
		command.Env = append(os.Environ(), "OPENSSL_CONF="+os.DevNull)
		stdin, err := command.StdinPipe()
		if err != nil {
			return err
		}
		stdout, err := command.StdoutPipe()
		if err != nil {
			return err
		}
		stderr, err := command.StderrPipe()
		if err != nil {
			return err
		}
		if err := command.Start(); err != nil {
			return fmt.Errorf("start SSL3 sidecar: %w", err)
		}
		writeEvents := make(chan int, 4)
		go relaySidecarDiagnostics(stderr, writeEvents)
		log.Printf("DS3 SSL3 sidecar listening on 0.0.0.0:%s for %s (openssl=%s capture=%s)", listenPort, address, openssl, capturePath)
		request, readErr := readBlazeFrame(stdout)
		replySent := false
		if readErr == nil {
			component, requestCommand, messageType, correlation := blazeMetadata(request)
			log.Printf("DS3 SSL3 redirector request component=%d command=%d type=%d correlation=%d bytes=%d",
				component, requestCommand, messageType, correlation, len(request))
			log.Printf("DS3 SSL3 redirector request frame=%s", hex.EncodeToString(request))
			capture.write("ssl3-redirector:request", request)
			if component == 5 && requestCommand == 1 && messageType == 0 {
				var reply []byte
				var replyErr error
				if secureBlaze {
					reply, replyErr = makeNFS13RedirectorReplyForRequest(
						request, advertiseHost, blazePort)
				} else {
					reply, replyErr = makeDS3RedirectorReplyForRequest(request, blazePort)
				}
				if replyErr == nil {
					// ZClient splits the Fire2 response after its first byte: the
					// leading zero of the two-byte body length is one SSL record and
					// the remaining 62 bytes are the next. Wait for the patched
					// sidecar's acknowledgements so pipe buffering cannot merge them.
					_, replyErr = stdin.Write(reply[:1])
				}
				if replyErr == nil {
					replyErr = waitSidecarWrite(ctx, writeEvents, 1)
				}
				if replyErr == nil {
					_, replyErr = stdin.Write(reply[1:])
				}
				if replyErr == nil {
					replyErr = waitSidecarWrite(ctx, writeEvents, len(reply)-1)
				}
				if replyErr != nil {
					log.Printf("DS3 SSL3 redirector reply failed: %v", replyErr)
				} else {
					log.Printf("DS3 SSL3 redirector reply frame=%s", hex.EncodeToString(reply))
					capture.write("ssl3-redirector:reply", reply)
					log.Printf("DS3 SSL3 redirector advertised localhost:%s via %s correlation=%d",
						strconv.Itoa(int(blazePort)), advertiseHost, correlation)
					replySent = true
				}
			}
		} else if ctx.Err() == nil && !errors.Is(readErr, io.EOF) {
			log.Printf("DS3 SSL3 redirector read failed: %v", readErr)
		}
		// This redirector is a one-request connection. Closing the sidecar pipe
		// after the complete Fire2 response makes the patched s_server flush the
		// SSL record and finish the session. Leaving it open makes DS3 wait for
		// connection completion and hit its ten-second redirector timeout.
		closeErr := stdin.Close()
		if replySent {
			if closeErr != nil {
				log.Printf("DS3 SSL3 redirector response-pipe close failed: %v", closeErr)
			} else {
				log.Printf("DS3 SSL3 redirector response flushed; closing one-shot session")
			}
		}
		if waitErr := command.Wait(); waitErr != nil && ctx.Err() == nil {
			log.Printf("DS3 SSL3 sidecar exited: %v", waitErr)
		}
	}
	return nil
}

// serveSSL3BlazeReplay terminates NFS13's SSL3 Blaze connection and bridges
// the decrypted byte stream to the normal Blaze replay server. OpenSSL is
// intentionally limited to the record/handshake layer; request matching,
// identity personalization, repeatable authentication, and replies remain in
// the Go backend.
func serveSSL3BlazeReplay(ctx context.Context, address string,
	certificate tls.Certificate, blaze *blazeServer) error {
	openssl, opensslVersion, err := findOpenSSL()
	if err != nil {
		return err
	}
	_, listenPort, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid SSL3 Blaze address %q: %w", address, err)
	}
	directory, err := os.MkdirTemp("", "zclient-ds3-blaze-ssl3-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	certPath, keyPath, chainPath, err := writeSidecarCertificate(directory, certificate)
	if err != nil {
		return err
	}
	log.Printf("NFS13 Blaze SSL3 runtime verified: %s (%s)", opensslVersion, openssl)

	for ctx.Err() == nil {
		arguments := []string{"s_server", "-accept", listenPort,
			"-cert", certPath, "-key", keyPath}
		if chainPath != "" {
			arguments = append(arguments, "-cert_chain", chainPath)
		}
		arguments = append(arguments, "-quiet", "-state", "-naccept", "1",
			"-ssl3", "-cipher", "AES256-SHA", "-bugs")
		command := exec.CommandContext(ctx, openssl, arguments...)
		command.Env = append(os.Environ(), "OPENSSL_CONF="+os.DevNull)
		stdin, err := command.StdinPipe()
		if err != nil {
			return err
		}
		stdout, err := command.StdoutPipe()
		if err != nil {
			return err
		}
		command.Stderr = os.Stderr
		if err := command.Start(); err != nil {
			return fmt.Errorf("start Blaze SSL3 sidecar: %w", err)
		}
		log.Printf("NFS13 SSL3 Blaze replay listening on 0.0.0.0:%s for %s",
			listenPort, address)

		// Do not start blaze.handle until OpenSSL has accepted a client and
		// produced its first decrypted frame. The handler applies a two-minute
		// idle deadline; starting it while s_server is merely listening makes a
		// backend that has been idle for two minutes reject the next game before
		// its SSL handshake can deliver any Blaze data.
		firstRequest, readErr := readBlazeFrame(stdout)
		if readErr != nil {
			_ = stdin.Close()
			if waitErr := command.Wait(); waitErr != nil && ctx.Err() == nil {
				log.Printf("NFS13 SSL3 Blaze sidecar exited before first frame: %v", waitErr)
			}
			if !errors.Is(readErr, io.EOF) && ctx.Err() == nil {
				log.Printf("NFS13 SSL3 Blaze first-frame read failed: %v", readErr)
			}
			continue
		}

		// net.Pipe supplies the deadline-capable net.Conn expected by the
		// regular Blaze handler while the two copy loops adapt OpenSSL's
		// separate stdin/stdout streams into one full-duplex connection.
		handlerConnection, sidecarConnection := net.Pipe()
		handlerDone := make(chan struct{})
		go func() {
			blaze.handle(handlerConnection)
			close(handlerDone)
		}()
		copyDone := make(chan error, 2)
		go func() {
			_, copyErr := sidecarConnection.Write(firstRequest)
			if copyErr == nil {
				_, copyErr = io.Copy(sidecarConnection, stdout)
			}
			copyDone <- copyErr
		}()
		go func() {
			_, copyErr := io.Copy(stdin, sidecarConnection)
			copyDone <- copyErr
		}()

		select {
		case <-ctx.Done():
		case <-handlerDone:
		case copyErr := <-copyDone:
			if copyErr != nil && !errors.Is(copyErr, io.EOF) &&
				!errors.Is(copyErr, net.ErrClosed) && ctx.Err() == nil {
				log.Printf("NFS13 SSL3 Blaze bridge disconnected: %v", copyErr)
			}
		}
		_ = sidecarConnection.Close()
		_ = stdin.Close()
		if waitErr := command.Wait(); waitErr != nil && ctx.Err() == nil {
			log.Printf("NFS13 SSL3 Blaze sidecar exited: %v", waitErr)
		}
	}
	return nil
}
