package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"time"
)

const nfs13AuxiliaryProbeAddress = "0.0.0.0:14988"

type bufferedProbeConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedProbeConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}

func serveNFS13AuxiliaryProbe(ctx context.Context, address string, blaze *blazeServer) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if errors.Is(acceptErr, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return acceptErr
		}
		go handleNFS13AuxiliaryProbe(connection, blaze)
	}
}

func handleNFS13AuxiliaryProbe(connection net.Conn, blaze *blazeServer) {
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReaderSize(connection, 16<<10)
	prefix, err := reader.Peek(12)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			log.Printf("NFS13 auxiliary client %s did not send a complete prefix: %v", connection.RemoteAddr(), err)
		}
		return
	}

	// Peek fills the buffered reader with whatever arrived in the same socket
	// record. Preserve a bounded copy in the log so an unknown auxiliary
	// protocol can be identified without another packet-hook change.
	buffered := reader.Buffered()
	if buffered > 4096 {
		buffered = 4096
	}
	sample, _ := reader.Peek(buffered)
	log.Printf("NFS13 auxiliary client %s prefix bytes=%d hex=%s text=%q",
		connection.RemoteAddr(), len(sample), hex.EncodeToString(sample), sample)

	component, command, messageType, correlation := blazeMetadata(prefix)
	bodySize := int(prefix[0])<<8 | int(prefix[1])
	if component != 0 && component <= 0x7fff && command != 0 && messageType == 0 && bodySize <= maxBlazeFrame {
		log.Printf("NFS13 auxiliary plaintext Fire2 component=%d command=%d correlation=%d; handing off to Blaze",
			component, command, correlation)
		_ = connection.SetReadDeadline(time.Time{})
		blaze.handle(&bufferedProbeConn{Conn: connection, reader: reader})
	}
}
