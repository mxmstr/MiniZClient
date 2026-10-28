package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

func redirectorTLSConfig(base *tls.Config) *tls.Config {
	config := base.Clone()
	// Captured ClientHello: TLS 1.1 with RSA/RC4 and RSA/AES-CBC suites.
	// Captured ServerHello selects exactly TLS_RSA_WITH_AES_256_CBC_SHA.
	config.MinVersion = tls.VersionTLS11
	config.MaxVersion = tls.VersionTLS11
	config.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA}
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		versions := make([]string, 0, len(hello.SupportedVersions))
		for _, version := range hello.SupportedVersions {
			versions = append(versions, fmt.Sprintf("%#04x", version))
		}
		ciphers := make([]string, 0, len(hello.CipherSuites))
		for _, cipher := range hello.CipherSuites {
			ciphers = append(ciphers, fmt.Sprintf("%#04x", cipher))
		}
		log.Printf("Blaze redirector ClientHello remote=%s sni=%q versions=[%s] ciphers=[%s]", hello.Conn.RemoteAddr(), hello.ServerName, strings.Join(versions, ","), strings.Join(ciphers, ","))
		return nil, nil
	}
	return config
}

func ds3RedirectorTLSConfig(base *tls.Config) *tls.Config {
	config := redirectorTLSConfig(base)
	// Dead Space 3's Win32 ProtoSSL build sends a pre-supported_versions
	// ClientHello with legacy_version TLS 1.0. Its offered AES-CBC suites are
	// already present in the shared redirector cipher list.
	config.MinVersion = tls.VersionTLS10
	config.MaxVersion = tls.VersionTLS10
	return config
}

type redirectorTLSListener struct {
	net.Listener
	config *tls.Config
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}

func (l redirectorTLSListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		reader := bufio.NewReader(raw)
		if hello, peekErr := reader.Peek(11); peekErr == nil &&
			len(hello) >= 11 && hello[0] == 0x16 && hello[5] == 0x01 {
			log.Printf("Blaze redirector raw ClientHello remote=%s record_version=%#04x client_version=%#04x",
				raw.RemoteAddr(), uint16(hello[1])<<8|uint16(hello[2]),
				uint16(hello[9])<<8|uint16(hello[10]))
		}
		connection := tls.Server(&bufferedConn{Conn: raw, reader: reader}, l.config)
		if err := connection.Handshake(); err != nil {
			log.Printf("Blaze redirector TLS failed remote=%s stage=handshake error=%v", raw.RemoteAddr(), err)
			_ = raw.Close()
			continue
		}
		state := connection.ConnectionState()
		log.Printf("Blaze redirector TLS established remote=%s version=%#04x cipher=%#04x resumed=%t", raw.RemoteAddr(), state.Version, state.CipherSuite, state.DidResume)
		return connection, nil
	}
}

func serveBlazeRedirector(listener net.Listener, config *tls.Config, advertiseHost, blazePort string) error {
	port, err := strconv.ParseUint(blazePort, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("invalid advertised Blaze port %q", blazePort)
	}
	tlsListener := redirectorTLSListener{Listener: listener, config: config}
	for {
		connection, err := tlsListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handleBlazeRedirector(connection, advertiseHost, uint16(port))
	}
}

func handleBlazeRedirector(connection net.Conn, advertiseHost string, blazePort uint16) {
	defer connection.Close()
	request, err := readBlazeFrame(connection)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			log.Printf("Blaze redirector read failed remote=%s error=%v", connection.RemoteAddr(), err)
		}
		return
	}
	component, command, messageType, correlation := blazeMetadata(request)
	log.Printf("Blaze redirector request remote=%s component=%d command=%d type=%d correlation=%d bytes=%d", connection.RemoteAddr(), component, command, messageType, correlation, len(request))
	if component != 5 || command != 1 || messageType != 0 {
		log.Printf("Blaze redirector rejected unexpected request")
		return
	}
	reply, err := makeRedirectorReply(correlation, advertiseHost, blazePort)
	if err != nil {
		log.Printf("Blaze redirector response build failed: %v", err)
		return
	}
	if _, err := connection.Write(reply); err != nil {
		log.Printf("Blaze redirector response write failed: %v", err)
		return
	}
	log.Printf("Blaze redirector advertised %s:%d correlation=%d", advertiseHost, blazePort, correlation)
}

func makeRedirectorReply(correlation uint32, host string, port uint16) ([]byte, error) {
	body, err := makeRedirectorBody(host, port, false)
	if err != nil {
		return nil, err
	}
	reply := make([]byte, 12+len(body))
	binary.BigEndian.PutUint16(reply[0:2], uint16(len(body)))
	binary.BigEndian.PutUint16(reply[2:4], 5)
	binary.BigEndian.PutUint16(reply[4:6], 1)
	reply[8] = 0x10
	setBlazeCorrelation(reply, correlation)
	copy(reply[12:], body)
	return reply, nil
}

// makeDS3RedirectorReplyForRequest mirrors FireFrame.CreateResponseFrame: the
// response keeps the request's user index, message number, options and any
// context header, while changing only the size, error and message type. DS3's
// generated decoder expects the compact legacy ServerInstanceInfo captured
// from ZClient: localhost/127.0.0.1 plus SECU=0 and XDNS=0. CLoader translates
// that loopback endpoint to the configured LAN service host.
func makeDS3RedirectorReplyForRequest(request []byte, port uint16) ([]byte, error) {
	return makeLegacyRedirectorReplyForRequest(request, "", port, false)
}

func makeNFS13RedirectorReplyForRequest(request []byte, host string, port uint16) ([]byte, error) {
	return makeLegacyRedirectorReplyForRequest(request, host, port, true)
}

func makeLegacyRedirectorReplyForRequest(request []byte, host string, port uint16,
	secure bool) ([]byte, error) {
	if len(request) < 12 {
		return nil, errors.New("redirector request header is truncated")
	}
	flags := request[9] >> 4
	headerSize := 12
	if flags&1 != 0 {
		headerSize += 2
	}
	if flags&2 != 0 {
		if flags&8 != 0 {
			headerSize += 8
		} else {
			headerSize += 4
		}
	} else if flags&8 != 0 {
		return nil, errors.New("redirector request has invalid Blaze frame flags")
	}
	if len(request) < headerSize {
		return nil, errors.New("redirector request extra header is truncated")
	}
	var body []byte
	var err error
	if secure {
		body, err = makeRedirectorBody(host, port, true)
	} else {
		body, err = makeDS3RedirectorBody(port)
	}
	if err != nil {
		return nil, err
	}
	if len(body) > 0xffff {
		return nil, errors.New("redirector response is too large")
	}
	header := append([]byte(nil), request[:headerSize]...)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(body)))
	header[6], header[7] = 0, 0
	header[8] = header[8]&0x0f | 0x10
	return append(header, body...), nil
}

func makeDS3RedirectorBody(port uint16) ([]byte, error) {
	address := []Field{
		{Tag: "HOST", Kind: 1, Value: []byte("localhost")},
		{Tag: "IP", Kind: 0, Value: int64(binary.BigEndian.Uint32(net.IPv4(127, 0, 0, 1).To4()))},
		{Tag: "PORT", Kind: 0, Value: int64(port)},
	}
	value := Field{Tag: "VALU", Kind: 3, Value: address}
	return encodeFields([]Field{
		{Tag: "ADDR", Kind: 6, Value: Union{Index: 0, Field: &value}},
		{Tag: "SECU", Kind: 0, Value: int64(0)},
		{Tag: "XDNS", Kind: 0, Value: int64(0)},
	}, 0)
}

func makeRedirectorBody(host string, port uint16, completeBlaze3Shape bool) ([]byte, error) {
	ip := net.ParseIP(host).To4()
	if ip == nil || ip[0] == 127 || ip.IsUnspecified() {
		return nil, fmt.Errorf("invalid advertised IPv4 address %q", host)
	}
	address := []Field{
		{Tag: "HOST", Kind: 1, Value: []byte(host)},
		{Tag: "IP", Kind: 0, Value: int64(binary.BigEndian.Uint32(ip))},
		{Tag: "PORT", Kind: 0, Value: int64(port)},
	}
	value := Field{Tag: "VALU", Kind: 3, Value: address}
	fields := []Field{
		{Tag: "ADDR", Kind: 6, Value: Union{Index: 0, Field: &value}},
	}
	if completeBlaze3Shape {
		// Blaze 3's generated ServerInstanceInfo decoder expects the complete
		// alphabetically encoded shape, including its empty certificate,
		// remap, and message lists. Dead Space 3 uses BlazeSDK 3.19.07.0,
		// whose ServerInstanceInfo inserts CERT between AMAP and MSGS. CERT
		// is a primitive vector of TdfBlob (wire kind 2), not a struct vector;
		// the generated decoder checks the element kind even when count is zero.
		fields = append(fields,
			Field{Tag: "AMAP", Kind: 4, Value: List{Kind: 3, Items: []any{}}},
			Field{Tag: "CERT", Kind: 4, Value: List{Kind: 2, Items: []any{}}},
			Field{Tag: "MSGS", Kind: 4, Value: List{Kind: 1, Items: []any{}}},
			Field{Tag: "NMAP", Kind: 4, Value: List{Kind: 3, Items: []any{}}})
	}
	fields = append(fields,
		Field{Tag: "SECU", Kind: 0, Value: int64(1)},
		Field{Tag: "XDNS", Kind: 0, Value: int64(0)},
	)
	body, err := encodeFields(fields, 0)
	if err != nil {
		return nil, err
	}
	if len(body) > 0xffff {
		return nil, errors.New("redirector response is too large")
	}
	return body, nil
}
