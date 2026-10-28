package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func TestGeneratedCertificateChainsToZLOCA(t *testing.T) {
	certificate, err := serviceCertificate("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	certificateBlock, _ := pem.Decode(zloTLSCertPEM)
	ca, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Subject.CommonName != "ZCertMaker" {
		t.Fatalf("CA common name = %q", ca.Subject.CommonName)
	}
	if err := ca.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatalf("leaf signature: %v", err)
	}
	for _, hostname := range []string{"localhost", "gosredirector.ea.com", "gosredirector.online.ea.com"} {
		if err := leaf.VerifyHostname(hostname); err != nil {
			t.Errorf("verify %s: %v", hostname, err)
		}
	}
}

func TestCompactLegacyCertificateStaysBelowDirtySSLRecordLimit(t *testing.T) {
	certificate, err := compactLegacyServiceCertificate("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.Certificate) != 1 {
		t.Fatalf("certificate chain length=%d, want the original direct-root leaf only",
			len(certificate.Certificate))
	}
	if size := len(certificate.Certificate[0]); size >= 900 {
		t.Fatalf("compact legacy certificate is %d bytes, want less than 900", size)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
		t.Fatalf("compact legacy leaf unexpectedly contains SANs: %#v %#v",
			leaf.DNSNames, leaf.IPAddresses)
	}
	if leaf.KeyUsage != 0 || len(leaf.ExtKeyUsage) != 0 {
		t.Fatalf("compact legacy leaf unexpectedly contains key-usage extensions: %v %#v",
			leaf.KeyUsage, leaf.ExtKeyUsage)
	}
	if leaf.Subject.CommonName != "winter15.gosredirector.ea.com" {
		t.Fatalf("compact legacy common name=%q, want recovered winter15 identity",
			leaf.Subject.CommonName)
	}
	_, remaining := pem.Decode(zloTLSCertPEM)
	rootBlock, _ := pem.Decode(remaining)
	if rootBlock == nil {
		t.Fatal("decode embedded ZLO root certificate")
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf.RawIssuer, root.RawSubject) {
		t.Fatalf("compact legacy issuer=%#v, want the direct ZLO root", leaf.Issuer)
	}
	if err := root.CheckSignature(leaf.SignatureAlgorithm,
		leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatalf("recovered leaf signature does not chain to the ZLO root: %v", err)
	}
}

func TestAssociationAddUsersReturnsEmptyUpdateVectors(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte(nil), server.corpus[0].request...)
	request[2], request[3] = 0, 25
	request[4], request[5] = 0, 1
	setBlazeCorrelation(request, 0x4567)

	reply, err := associationUpdateReply(request)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 25 || command != 1 || messageType != 1 || correlation != 0x4567 {
		t.Fatalf("unexpected response metadata: component=%d command=%d type=%d correlation=%d",
			component, command, messageType, correlation)
	}
	packet, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"LMID", "REM"} {
		field, err := fieldAt(packet.Fields, tag, 4)
		if err != nil {
			t.Fatal(err)
		}
		list, ok := field.Value.(List)
		if !ok || list.Kind != 3 || len(list.Items) != 0 {
			t.Fatalf("%s=%#v, want empty struct list", tag, field.Value)
		}
	}
}

func TestSetClientMetricsReturnsEmptySuccess(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte(nil), server.corpus[0].request...)
	request[2], request[3] = 0, 9
	request[4], request[5] = 0, 22
	setBlazeCorrelation(request, 0x5678)
	reply, err := emptySuccessReply(request)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 9 || command != 22 || messageType != 1 || correlation != 0x5678 {
		t.Fatalf("unexpected response metadata: component=%d command=%d type=%d correlation=%d",
			component, command, messageType, correlation)
	}
	packet, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Fields) != 0 {
		t.Fatalf("setClientMetrics response has %d fields, want none", len(packet.Fields))
	}
}

func TestNFS13RoadRulesUpdateReturnsEmptySuccess(t *testing.T) {
	request, err := hex.DecodeString("00d50801000b00000000001c8aca6400a401ca5c73040306976bb400b287e901d39c25010a526f616452756c657300d69ba60000da5d39000200976bb4009eb538d39c25010a526f616452756c657300d69ba60001da5d39000200976bb4008890b001d39c25010a526f616452756c657300d69ba60002da5d39000200976bb40094a77dd39c25010a526f616452756c657300d69ba60003da5d39000200976bb40095e4b301d39c25010a526f616452756c657300d69ba60004da5d39000200976bb4009c8b78d39c25010a526f616452756c657300d69ba60005da5d39000200")
	if err != nil {
		t.Fatal(err)
	}
	reply, err := emptySuccessReply(request)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 0x0801 || command != 11 || messageType != 1 || correlation != 28 {
		t.Fatalf("unexpected response metadata: component=%d command=%d type=%d correlation=%d",
			component, command, messageType, correlation)
	}
	packet, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Fields) != 0 {
		t.Fatalf("RoadRules response has %d fields, want EmptyMessage", len(packet.Fields))
	}
}

func TestNFS13HardwareFlagsUpdatesReturnEmptySuccess(t *testing.T) {
	for _, encoded := range []string{
		"000578020008000000000009a379a70000",
		"00057802000800000000000fa379a70001",
	} {
		request, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := emptySuccessReply(request)
		if err != nil {
			t.Fatal(err)
		}
		component, command, messageType, correlation := blazeMetadata(reply)
		_, _, _, wantCorrelation := blazeMetadata(request)
		if component != 0x7802 || command != 8 || messageType != 1 || correlation != wantCorrelation {
			t.Fatalf("unexpected response metadata: component=%d command=%d type=%d correlation=%d; want correlation=%d",
				component, command, messageType, correlation, wantCorrelation)
		}
		packet, err := decodePacket(reply)
		if err != nil {
			t.Fatal(err)
		}
		if len(packet.Fields) != 0 {
			t.Fatalf("hardware-flags response has %d fields, want EmptyMessage", len(packet.Fields))
		}
	}
}

func TestCancelMatchmakingReturnsEmptySuccess(t *testing.T) {
	request, err := hex.DecodeString("00050004000e000000000026b73a640002")
	if err != nil {
		t.Fatal(err)
	}
	reply, err := emptySuccessReply(request)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 4 || command != 14 || messageType != 1 || correlation != 38 {
		t.Fatalf("unexpected response metadata: component=%d command=%d type=%d correlation=%d",
			component, command, messageType, correlation)
	}
}

func TestAdvanceGameStateGeneratesLiveStateNotification(t *testing.T) {
	request, err := (Packet{
		Header: []byte{0, 0, 0, 4, 0, 3, 0, 0, 0, 0, 0, 0},
		Fields: []Field{
			{Tag: "GID", Kind: 0, Value: int64(0x1234)},
			{Tag: "GSTA", Kind: 0, Value: int64(132)},
		},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	setBlazeCorrelation(request, 0x45678)
	replies, err := advanceGameStateReplies(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(replies) != 2 {
		t.Fatalf("advance-state reply count = %d, want 2", len(replies))
	}
	component, command, messageType, correlation := blazeMetadata(replies[0])
	if component != 4 || command != 3 || messageType != 1 || correlation != 0x45678 {
		t.Fatalf("response metadata = %d/%d type %d correlation %#x", component, command, messageType, correlation)
	}
	component, command, messageType, correlation = blazeMetadata(replies[1])
	if component != 4 || command != 100 || messageType != 2 || correlation != 0 {
		t.Fatalf("notification metadata = %d/%d type %d correlation %#x", component, command, messageType, correlation)
	}
	notification, err := decodePacket(replies[1])
	if err != nil {
		t.Fatal(err)
	}
	gameID, gameIDErr := integerField(notification.Fields, "GID")
	state, stateErr := integerField(notification.Fields, "GSTA")
	if gameIDErr != nil || stateErr != nil || gameID != 0x1234 || state != 132 {
		t.Fatalf("notification GID/GSTA = %d/%d, errors %v/%v", gameID, state, gameIDErr, stateErr)
	}
}

func TestAdvanceGameStateMatchesCapturedReplies(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for _, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component != 4 || command != 3 {
			continue
		}
		generated, err := advanceGameStateReplies(entry.request)
		if err != nil {
			t.Fatal(err)
		}
		if len(generated) != len(entry.replies) {
			t.Fatalf("generated %d replies, captured %d", len(generated), len(entry.replies))
		}
		for index := range generated {
			if !bytes.Equal(generated[index], entry.replies[index]) {
				t.Fatalf("reply %d differs from captured advance-state response", index)
			}
		}
		matched++
	}
	if matched != 2 {
		t.Fatalf("matched %d captured advance-state requests, want 2", matched)
	}
}

func TestSetGameSettingsGeneratesLiveSettingsNotification(t *testing.T) {
	// Exact component-4/command-4 request from NFS13's v42 friends-game run.
	request, err := hex.DecodeString("000d000400040000000000279e9900008080089f3974009c04")
	if err != nil {
		t.Fatal(err)
	}
	replies, err := setGameSettingsReplies(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(replies) != 2 {
		t.Fatalf("set-game-settings reply count = %d, want 2", len(replies))
	}
	component, command, messageType, correlation := blazeMetadata(replies[0])
	if component != 4 || command != 4 || messageType != 1 || correlation != 39 {
		t.Fatalf("response metadata = %d/%d type %d correlation %d", component, command, messageType, correlation)
	}
	response, err := decodePacket(replies[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Fields) != 0 {
		t.Fatalf("set-game-settings response has %d fields, want EmptyMessage", len(response.Fields))
	}
	wantResponse, err := hex.DecodeString("000000040004000010000027")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replies[0], wantResponse) {
		t.Fatalf("response = %x, want %x", replies[0], wantResponse)
	}
	component, command, messageType, correlation = blazeMetadata(replies[1])
	if component != 4 || command != 110 || messageType != 2 || correlation != 0 {
		t.Fatalf("notification metadata = %d/%d type %d correlation %d", component, command, messageType, correlation)
	}
	notification, err := decodePacket(replies[1])
	if err != nil {
		t.Fatal(err)
	}
	gameID, gameIDErr := integerField(notification.Fields, "GID")
	settings, settingsErr := integerField(notification.Fields, "ATTR")
	if gameIDErr != nil || settingsErr != nil || gameID != 65536 || settings != 284 {
		t.Fatalf("notification GID/ATTR = %d/%d, errors %v/%v", gameID, settings, gameIDErr, settingsErr)
	}
	if _, err := fieldAt(notification.Fields, "GSET", 0); err == nil {
		t.Fatal("settings notification retained request-only GSET field")
	}
	wantNotification, err := hex.DecodeString("000d0004006e000020000000874d32009c049e990000808008")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replies[1], wantNotification) {
		t.Fatalf("notification = %x, want %x", replies[1], wantNotification)
	}
}

func TestListUserEntitlements2ReturnsTypedEmptyList(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte(nil), server.corpus[0].request...)
	request[2], request[3] = 0, 1
	request[4], request[5] = 0, 29
	setBlazeCorrelation(request, 0x6789)
	reply, err := userEntitlementsReply(request)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 1 || command != 29 || messageType != 1 || correlation != 0x6789 {
		t.Fatalf("unexpected response metadata: component=%d command=%d type=%d correlation=%d",
			component, command, messageType, correlation)
	}
	packet, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	field, err := fieldAt(packet.Fields, "NLST", 4)
	if err != nil {
		t.Fatal(err)
	}
	list, ok := field.Value.(List)
	if !ok || list.Kind != 3 || len(list.Items) != 0 {
		t.Fatalf("NLST=%#v, want empty struct list", field.Value)
	}
}

func TestBlazeCorpusContainsStartupAndAuthentication(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(server.corpus); got != 202 {
		t.Fatalf("replay corpus has %d entries, want 202", got)
	}
	wanted := map[[2]uint16]bool{
		{9, 7}:       false,
		{1, 152}:     false,
		{0x7802, 20}: false,
		{1, 230}:     false,
		{1, 30}:      false,
		{9, 10}:      false,
		{7, 15}:      false,
		{0x7802, 8}:  false,
		{0x0802, 38}: false,
		{4, 13}:      false,
	}
	for _, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		key := [2]uint16{component, command}
		if _, ok := wanted[key]; ok && len(entry.replies) != 0 {
			wanted[key] = true
		}
	}
	for key, found := range wanted {
		if !found {
			t.Errorf("replay corpus lacks response for component=%d command=%d", key[0], key[1])
		}
	}
}

func TestBlazeTLSReplaysAndRewritesCorrelation(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = server.serve(listener) }()

	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, // The production endpoint intentionally uses a local self-signed certificate.
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	request := append([]byte(nil), server.corpus[0].request...)
	const correlation = 0x54321
	setBlazeCorrelation(request, correlation)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply, err := readBlazeFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, actualCorrelation := blazeMetadata(reply)
	if component != 9 || command != 7 || messageType != 1 {
		t.Fatalf("unexpected response metadata: component=%d command=%d type=%d", component, command, messageType)
	}
	if actualCorrelation != correlation {
		t.Fatalf("response correlation = %#x, want %#x", actualCorrelation, correlation)
	}
}

func TestBlazeReplayReusesLastExactRequestAfterCorpusExhaustion(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	request := server.corpus[1].request // component 9, command 2 keepalive
	index, exact, reused := server.findReplay(request, len(server.corpus))
	wantIndex := len(server.corpus) - 1
	if index != wantIndex || !exact || !reused {
		t.Fatalf("findReplay = (%d, %t, %t), want (%d, true, true)", index, exact, reused, wantIndex)
	}
}

func TestBlazeReplayReusesLatestNetworkInfoForChangedPayload(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	latest := -1
	for index, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component == 0x7802 && command == 20 {
			latest = index
		}
	}
	if latest < 0 {
		t.Fatal("replay corpus lacks UpdateNetworkInfo")
	}
	request := append([]byte(nil), server.corpus[latest].request...)
	request[len(request)-1] ^= 1 // Simulate a changed live QoS/NAT measurement.
	setBlazeCorrelation(request, 57)
	index, exact, reused := server.findReplay(request, len(server.corpus))
	if index != latest || exact || !reused {
		t.Fatalf("findReplay = (%d, %t, %t), want (%d, false, true)", index, exact, reused, latest)
	}
}

func TestBlazeReplayReusesPrivateUserSessionCommand13ForChangedIdentity(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	latest := -1
	for index, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component == 0x7802 && command == 13 {
			latest = index
		}
	}
	if latest < 0 {
		t.Fatal("replay corpus lacks private UserSessions command 13")
	}
	request := append([]byte(nil), server.corpus[latest].request...)
	request[len(request)-1] ^= 1 // Simulate the distinct live player identity.
	setBlazeCorrelation(request, 211)
	index, exact, reused := server.findReplay(request, len(server.corpus))
	if index != latest || exact || !reused {
		t.Fatalf("findReplay = (%d, %t, %t), want (%d, false, true)", index, exact, reused, latest)
	}
	if got := len(server.corpus[index].replies); got != 1 {
		t.Fatalf("command 13 reply count = %d, want 1", got)
	}
	reply := append([]byte(nil), server.corpus[index].replies[0]...)
	setBlazeCorrelation(reply, 211)
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 0x7802 || command != 13 || messageType != 1 || correlation != 211 {
		t.Fatalf("reply metadata = %04x/%d type %d correlation %d, want 7802/13 type 1 correlation 211",
			component, command, messageType, correlation)
	}
}

func TestBlazeReplayReusesStartMatchmakingAfterStartupCursor(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	latest := -1
	for index, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component == 4 && command == 13 {
			latest = index
		}
	}
	if latest < 0 {
		t.Fatal("replay corpus lacks startMatchmaking")
	}
	request := append([]byte(nil), server.corpus[latest].request...)
	request[len(request)-1] ^= 1 // Simulate NFS13's distinct matchmaking criteria.
	setBlazeCorrelation(request, 33)
	index, exact, reused := server.findReplay(request, len(server.corpus))
	if index != latest || exact || !reused {
		t.Fatalf("findReplay = (%d, %t, %t), want (%d, false, true)", index, exact, reused, latest)
	}
	if got := len(server.corpus[index].replies); got != 2 {
		t.Fatalf("startMatchmaking reply count = %d, want response plus setup notification", got)
	}
	component, command, messageType, _ := blazeMetadata(server.corpus[index].replies[1])
	if component != 4 || command != 20 || messageType != 2 {
		t.Fatalf("setup notification = %d/%d type %d, want 4/20 type 2",
			component, command, messageType)
	}
}

func TestBlazeReplayReusesLatestGameReportForChangedPayload(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	latest := -1
	for index, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component == 28 && command == 2 {
			latest = index
		}
	}
	if latest < 0 {
		t.Fatal("replay corpus lacks submitGameReport")
	}
	request := append([]byte(nil), server.corpus[latest].request...)
	request[len(request)-1] ^= 1 // Simulate different statistics in a later report.
	setBlazeCorrelation(request, 207)
	index, exact, reused := server.findReplay(request, len(server.corpus))
	if index != latest || exact || !reused {
		t.Fatalf("findReplay = (%d, %t, %t), want (%d, false, true)", index, exact, reused, latest)
	}
	if got := len(server.corpus[index].replies); got != 2 {
		t.Fatalf("submitGameReport reply count = %d, want 2", got)
	}
	component, command, messageType, _ := blazeMetadata(server.corpus[index].replies[0])
	if component != 28 || command != 2 || messageType != 1 {
		t.Fatalf("reply metadata = %d/%d type %d, want 28/2 type 1", component, command, messageType)
	}
	component, command, messageType, _ = blazeMetadata(server.corpus[index].replies[1])
	if component != 28 || command != 114 || messageType != 2 {
		t.Fatalf("notification metadata = %d/%d type %d, want 28/114 type 2", component, command, messageType)
	}
}

func TestUserSessionsNetworkInfoReplayFollowsPostAuth(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	const entryIndex = 4
	entry := server.corpus[entryIndex]
	component, command, messageType, _ := blazeMetadata(entry.request)
	if component != 0x7802 || command != 20 || messageType != 0 {
		t.Fatalf("request metadata = %04x/%d type %d, want 7802/20 type 0", component, command, messageType)
	}
	if len(entry.replies) != 2 {
		t.Fatalf("UserSessions network-info reply count = %d, want 2", len(entry.replies))
	}
	component, command, messageType, correlation := blazeMetadata(entry.replies[0])
	if component != 0x7802 || command != 20 || messageType != 1 || correlation != 0 {
		t.Fatalf("reply metadata = %04x/%d type %d correlation %d, want 7802/20 type 1 correlation 0",
			component, command, messageType, correlation)
	}
	component, command, messageType, correlation = blazeMetadata(entry.replies[1])
	if component != 0x7802 || command != 1 || messageType != 2 || correlation != 0 {
		t.Fatalf("notification metadata = %04x/%d type %d correlation %d, want 7802/1 type 2 correlation 0",
			component, command, messageType, correlation)
	}
}

func TestNFS13NetworkInfoRefreshAlwaysPublishesSessionData(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	server.nfs13 = true
	client, backend := net.Pipe()
	defer client.Close()
	go server.handle(backend)
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	requests := []string{
		"007f780200140000000000068649320602da1b3503978a7003a700000000c2fcb4000000a6ea7003a70000008793c08a18c2fcb4008b390000bacb70050100040862696f2d69616400bfbff8ff010862696f2d736a6300bfbff8ff010862696f2d73796400bfbff8ff010765612d616d7300bfbff8ff01bb1bf303922c330000ba1d340005d62c33000000",
		"0077780200140000000000148649320602da1b3503978a7003a7000000b0d3f48303c2fcb4008b3900a6ea7003a70000008793c08a18c2fcb4008b390000bacb70050100040862696f2d696164001a0862696f2d736a63009b010862696f2d73796400be030765612d616d7300a901bb1bf303922c330000ba1d340005d62c33000000",
	}
	for attempt, encoded := range requests {
		request, decodeErr := hex.DecodeString(encoded)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if _, writeErr := client.Write(request); writeErr != nil {
			t.Fatalf("network-info attempt %d write: %v", attempt+1, writeErr)
		}
		reply, readErr := readBlazeFrame(client)
		if readErr != nil {
			t.Fatalf("network-info attempt %d response: %v", attempt+1, readErr)
		}
		component, command, messageType, correlation := blazeMetadata(reply)
		if len(reply) != 12 || component != 0x7802 || command != 20 || messageType != 1 ||
			correlation != uint32(request[11]) {
			t.Fatalf("network-info response %d = len %d %04x/%d type %d correlation %d",
				attempt+1, len(reply), component, command, messageType, correlation)
		}
		notification, readErr := readBlazeFrame(client)
		if readErr != nil {
			t.Fatalf("network-info attempt %d notification: %v", attempt+1, readErr)
		}
		component, command, messageType, correlation = blazeMetadata(notification)
		if len(notification) != 125 || component != 0x7802 || command != 1 ||
			messageType != 2 || correlation != 0 {
			t.Fatalf("network-info notification %d = len %d %04x/%d type %d correlation %d",
				attempt+1, len(notification), component, command, messageType, correlation)
		}
	}
}

func TestUserSessionsProbeReplyMatchesEAHandler(t *testing.T) {
	const correlation = 0x54321
	reply := userSessionsProbeReply(correlation)
	component, command, messageType, actualCorrelation := blazeMetadata(reply)
	if component != 0x7802 || command != 35 || messageType != 3 || actualCorrelation != correlation {
		t.Fatalf("probe reply metadata = %04x/%d type %d correlation %#x, want 7802/35 type 3 correlation %#x",
			component, command, messageType, actualCorrelation, correlation)
	}
	packet, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Fields) != 1 || packet.Fields[0].Tag != "ERRC" || packet.Fields[0].Kind != 0 || packet.Fields[0].Value != int64(0) {
		t.Fatalf("probe reply fields = %#v, want ERRC integer 0", packet.Fields)
	}
}

func TestSoftwareProductReplyEchoesRequestedIDs(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	var request, capturedReply []byte
	for _, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component == 0x0802 && command == 20 {
			request = append([]byte(nil), entry.request...)
			capturedReply = append([]byte(nil), entry.replies[0]...)
			break
		}
	}
	if request == nil {
		t.Fatal("replay corpus lacks software-product request")
	}
	generated, err := softwareProductReply(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, capturedReply) {
		t.Fatalf("generated captured response differs: got %x, want %x", generated, capturedReply)
	}
	packet, err := decodePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	softwareIDs, err := fieldAt(packet.Fields, "SWIS", 4)
	if err != nil {
		t.Fatal(err)
	}
	softwareIDs.Value = List{Kind: 0, Items: []any{int64(1234), int64(5678)}}
	request, err = packet.Encode()
	if err != nil {
		t.Fatal(err)
	}
	setBlazeCorrelation(request, 201)
	reply, err := softwareProductReply(request)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 0x0802 || command != 20 || messageType != 1 || correlation != 201 {
		t.Fatalf("reply metadata = %04x/%d type %d correlation %d", component, command, messageType, correlation)
	}
	decoded, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	softwareProducts, err := fieldAt(decoded.Fields, "SPWA", 4)
	if err != nil {
		t.Fatal(err)
	}
	list, ok := softwareProducts.Value.(List)
	if !ok || list.Kind != 3 || len(list.Items) != 2 {
		t.Fatalf("SPWA = %#v, want two structs", softwareProducts.Value)
	}
	for index, want := range []int64{1234, 5678} {
		fields, ok := list.Items[index].([]Field)
		if !ok {
			t.Fatalf("SPWA[%d] has type %T", index, list.Items[index])
		}
		got, err := integerField(fields, "SWID")
		if err != nil || got != want {
			t.Fatalf("SPWA[%d].SWID = %d, %v; want %d", index, got, err, want)
		}
	}
}

func TestZClientStateRepliesAreCorrelatedEmptySuccess(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	var request []byte
	for _, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component == 0x0802 && command == 20 {
			packet, decodeErr := decodePacket(entry.request)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			packet.Header[4], packet.Header[5] = 0, 29
			packet.Fields = []Field{{Tag: "BLID", Kind: 0, Value: int64(2)}}
			request, err = packet.Encode()
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if request == nil {
		t.Fatal("replay corpus lacks a template for the ZClient request")
	}
	for _, command := range []uint16{29, 21} {
		request[4], request[5] = byte(command>>8), byte(command)
		setBlazeCorrelation(request, 212+uint32(29-command))
		reply, replyErr := emptySuccessReply(request)
		if replyErr != nil {
			t.Fatal(replyErr)
		}
		component, actualCommand, messageType, correlation := blazeMetadata(reply)
		wantCorrelation := 212 + uint32(29-command)
		if component != 0x0802 || actualCommand != command || messageType != 1 || correlation != wantCorrelation {
			t.Fatalf("reply metadata = %04x/%d type %d correlation %d, want 0802/%d type 1 correlation %d",
				component, actualCommand, messageType, correlation, command, wantCorrelation)
		}
		packet, decodeErr := decodePacket(reply)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if len(packet.Fields) != 0 || len(reply) != 12 {
			t.Fatalf("command %d void reply has %d fields and %d bytes, want 0 fields and 12 bytes",
				command, len(packet.Fields), len(reply))
		}
	}
}

func TestGameManagerMeshConnectionReplyIsCorrelatedEmptySuccess(t *testing.T) {
	request := Packet{
		Header: []byte{0, 0, 0, 4, 0, 29, 0, 0, 0, 0, 0, 234},
		Fields: []Field{
			{Tag: "GID", Kind: 0, Value: int64(65536)},
			{Tag: "TARG", Kind: 0, Value: int64(111437703)},
		},
	}
	encoded, err := request.Encode()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := emptySuccessReply(encoded)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 4 || command != 29 || messageType != 1 || correlation != 234 {
		t.Fatalf("reply metadata = %d/%d type %d correlation %d, want 4/29 type 1 correlation 234",
			component, command, messageType, correlation)
	}
	packet, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Fields) != 0 || len(reply) != 12 {
		t.Fatalf("mesh reply has %d fields and %d bytes, want 0 fields and 12 bytes",
			len(packet.Fields), len(reply))
	}
}

func TestGameManagerAddAdminReplyIsCorrelatedEmptySuccess(t *testing.T) {
	request, err := (Packet{
		Header: []byte{0, 0, 0, 4, 0, 106, 0, 0, 0, 0, 0, 0},
		Fields: []Field{{Tag: "GID", Kind: 0, Value: int64(65536)}, {Tag: "PID", Kind: 0, Value: int64(111437703)}},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	setBlazeCorrelation(request, 219)
	reply, err := emptySuccessReply(request)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 4 || command != 106 || messageType != 1 || correlation != 219 {
		t.Fatalf("reply metadata = %d/%d type %d correlation %d, want 4/106 type 1 correlation 219",
			component, command, messageType, correlation)
	}
}

func TestGameManagerLobbyLifecycleRepliesAreCorrelatedEmptySuccess(t *testing.T) {
	for _, command := range []uint16{11, 15} {
		request, err := (Packet{
			Header: []byte{0, 0, 0, 4, byte(command >> 8), byte(command), 0, 0, 0, 0, 0, 0},
			Fields: []Field{{Tag: "GID", Kind: 0, Value: int64(65536)}},
		}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		setBlazeCorrelation(request, 300+uint32(command))
		reply, err := emptySuccessReply(request)
		if err != nil {
			t.Fatal(err)
		}
		component, actualCommand, messageType, correlation := blazeMetadata(reply)
		if component != 4 || actualCommand != command || messageType != 1 || correlation != 300+uint32(command) {
			t.Fatalf("command %d reply metadata = %d/%d type %d correlation %d",
				command, component, actualCommand, messageType, correlation)
		}
		packet, err := decodePacket(reply)
		if err != nil {
			t.Fatal(err)
		}
		if len(packet.Fields) != 0 {
			t.Fatalf("command %d reply has %d fields, want empty", command, len(packet.Fields))
		}
	}
}

func TestNFS13CreateOnlyMatchmakingPreservesLiveLobbyAttributes(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	var setup []byte
	for _, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component != 4 || command != 13 {
			continue
		}
		for _, reply := range entry.replies {
			rComponent, rCommand, rType, _ := blazeMetadata(reply)
			if rComponent == 4 && rCommand == 20 && rType == 2 {
				setup = append([]byte(nil), reply...)
			}
		}
		break
	}
	if setup == nil {
		t.Fatal("replay corpus lacks matchmaking setup")
	}
	request, err := (Packet{
		Header: []byte{0, 0, 0, 4, 0, 13, 0, 0, 0, 0, 0, 1},
		Fields: []Field{
			{Tag: "ATTR", Kind: 5, Value: MapValue{KeyKind: 1, ValueKind: 1, Pairs: []Pair{
				{Key: []byte("current_event"), Value: []byte("390703")},
				{Key: []byte("visibility"), Value: []byte("1")},
			}}},
			{Tag: "MODE", Kind: 0, Value: int64(2)},
		},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}

	rewritten, createOnly, err := nfs13MatchmakingSetup(request, setup)
	if err != nil {
		t.Fatal(err)
	}
	if !createOnly {
		t.Fatal("MODE=2 was not recognized as create-only")
	}
	rewrittenPacket, err := decodePacket(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	gameFields, err := structField(rewrittenPacket.Fields, "GAME")
	if err != nil {
		t.Fatal(err)
	}
	gotAttributes, err := mapField(gameFields, "ATTR")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"current_event": "390703",
		"visibility":    "1",
	}
	for _, pair := range gotAttributes.Pairs {
		key := string(pair.Key.([]byte))
		if expected, ok := want[key]; ok {
			if got := string(pair.Value.([]byte)); got != expected {
				t.Fatalf("attribute %s = %q, want %q", key, got, expected)
			}
			delete(want, key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("rewritten setup lacks live attributes: %v", want)
	}
}

func TestNFS13ResetDedicatedServerCreatesPrivateGameSetup(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	request, err := (Packet{
		Header: []byte{0, 0, 0, 4, 0, 25, 0, 0, 0, 0, 0, 32},
		Fields: []Field{
			{Tag: "ATTR", Kind: 5, Value: MapValue{KeyKind: 1, ValueKind: 1, Pairs: []Pair{
				{Key: []byte("current_event"), Value: []byte("1113775")},
				{Key: []byte("round"), Value: []byte("0")},
				{Key: []byte("visibility"), Value: []byte("3")},
			}}},
			{Tag: "GCTR", Kind: 1, Value: []byte{}},
			{Tag: "GNAM", Kind: 1, Value: []byte{}},
			{Tag: "GSET", Kind: 0, Value: int64(284)},
			{Tag: "NTOP", Kind: 0, Value: int64(132)},
			{Tag: "PCAP", Kind: 4, Value: List{Kind: 0, Items: []any{int64(12), int64(0)}}},
			// NFS13's live resetDedicatedServer request leaves PMAX at zero. The
			// server must derive MCAP from PCAP instead of copying this default.
			{Tag: "PMAX", Kind: 0, Value: int64(0)},
			{Tag: "PRES", Kind: 0, Value: int64(1)},
			{Tag: "QCAP", Kind: 0, Value: int64(132)},
			{Tag: "TIDX", Kind: 0, Value: int64(65535)},
			{Tag: "VOIP", Kind: 0, Value: int64(2)},
			{Tag: "VSTR", Kind: 1, Value: []byte("Retail-0.7")},
		},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}

	replies, err := server.nfs13ResetDedicatedServerReplies(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(replies) != 2 {
		t.Fatalf("reset-dedicated-server returned %d frames, want 2", len(replies))
	}
	component, command, messageType, correlation := blazeMetadata(replies[0])
	if component != 4 || command != 25 || messageType != 1 || correlation != 32 {
		t.Fatalf("reset reply = %d/%d type %d correlation %d, want 4/25 type 1 correlation 32",
			component, command, messageType, correlation)
	}
	component, command, messageType, correlation = blazeMetadata(replies[1])
	if component != 4 || command != 20 || messageType != 2 || correlation != 0 {
		t.Fatalf("setup template = %d/%d type %d correlation %d, want 4/20 type 2 correlation 0",
			component, command, messageType, correlation)
	}

	identity := &blazeIdentity{name: "host", token: []byte("host"), id: 1001}
	setup, _, err := personalizeReplayReply(replies[1], time.Now().Unix(), identity)
	if err != nil {
		t.Fatal(err)
	}
	setup, err = nfs13ResetDedicatedServerSetup(request, setup)
	if err != nil {
		t.Fatal(err)
	}
	registry := newRegistry(time.Minute, false, false)
	registered, err := registry.exchangeSetup("blaze:host", setup, false)
	if err != nil {
		t.Fatal(err)
	}
	gameID := registry.gameID("blaze:host")
	if gameID == 0 || registry.games[gameID] == nil || registry.games[gameID].Matchable {
		t.Fatalf("friends game registration = id %d game %#v; want a private game", gameID, registry.games[gameID])
	}

	setupPacket, err := decodePacket(registered)
	if err != nil {
		t.Fatal(err)
	}
	gameFields, err := structField(setupPacket.Fields, "GAME")
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := mapField(gameFields, "ATTR")
	if err != nil {
		t.Fatal(err)
	}
	if len(attributes.Pairs) != 1 ||
		string(attributes.Pairs[0].Key.([]byte)) != "gameMembershipRequirements" ||
		string(attributes.Pairs[0].Value.([]byte)) != "FriendsOnly" {
		t.Fatalf("friends-game setup attributes = %#v; want FriendsOnly membership only", attributes.Pairs)
	}
	for tag, expected := range map[string]int64{
		"GSET": 287, "MCAP": 6, "NTOP": 133, "PRES": 1,
		"QCAP": 0, "VOIP": 1,
	} {
		actual, fieldErr := integerField(gameFields, tag)
		if fieldErr != nil || actual != expected {
			t.Fatalf("setup %s = %d, error %v; want %d", tag, actual, fieldErr, expected)
		}
	}
	capacities, err := listField(gameFields, "CAP")
	if err != nil || capacities.Kind != 0 || len(capacities.Items) != 4 {
		t.Fatalf("setup capacities = %#v, error %v; want [6,0,0,0]", capacities, err)
	}
	for index, expected := range []int64{6, 0, 0, 0} {
		actual, ok := capacities.Items[index].(int64)
		if !ok || actual != expected {
			t.Fatalf("setup capacity %d = %v; want %d", index, capacities.Items[index], expected)
		}
	}
	for tag, expected := range map[string]string{"GNAM": "host", "PSAS": "zlo"} {
		field, fieldErr := fieldAt(gameFields, tag, 1)
		if fieldErr != nil || string(field.Value.([]byte)) != expected {
			t.Fatalf("setup %s = %v, error %v; want %q", tag, field, fieldErr, expected)
		}
	}
	roleInfo, err := structField(gameFields, "RNFO")
	if err != nil {
		t.Fatal(err)
	}
	roleCriteria, err := mapField(roleInfo, "CRIT")
	if err != nil || roleCriteria.ValueKind != 3 || len(roleCriteria.Pairs) != 1 {
		t.Fatalf("setup role criteria = %#v, error %v", roleCriteria, err)
	}
	role, ok := roleCriteria.Pairs[0].Value.([]Field)
	if !ok {
		t.Fatalf("setup role = %T, want struct", roleCriteria.Pairs[0].Value)
	}
	roleCapacity, err := integerField(role, "RCAP")
	if err != nil || roleCapacity != 6 {
		t.Fatalf("setup role capacity = %d, error %v; want 6", roleCapacity, err)
	}
	roster, err := listField(setupPacket.Fields, "PROS")
	if err != nil || roster.Kind != 3 || len(roster.Items) != 1 {
		t.Fatalf("setup roster = %#v, error %v", roster, err)
	}
	hostPlayer, ok := roster.Items[0].([]Field)
	if !ok {
		t.Fatalf("setup host player = %T, want struct", roster.Items[0])
	}
	if teamIndex, teamErr := integerField(hostPlayer, "TIDX"); teamErr == nil {
		t.Fatalf("setup team index = %d; want accepted template default omitted", teamIndex)
	}
	version, err := fieldAt(gameFields, "VSTR", 1)
	if err != nil || string(version.Value.([]byte)) != "591487325" {
		t.Fatalf("setup VSTR = %v, error %v; want 591487325", version, err)
	}
	reason, err := unionField(setupPacket.Fields, "REAS")
	if err != nil || reason.Index != 1 || reason.Field == nil || reason.Field.Kind != 3 {
		t.Fatalf("setup reason = %#v, error %v; want reset-dedicated-server context", reason, err)
	}
	reasonFields, ok := reason.Field.Value.([]Field)
	if !ok {
		t.Fatalf("setup reason payload = %T, want struct", reason.Field.Value)
	}
	joinError, err := integerField(reasonFields, "ERR")
	if err != nil || joinError != 0 {
		t.Fatalf("setup reset join error = %d, error %v; want 0", joinError, err)
	}
}

func TestDestroyGameReplyIncludesGameID(t *testing.T) {
	request, err := (Packet{
		Header: []byte{0, 0, 0, 4, 0, 2, 0, 0, 0, 0, 0, 33},
		Fields: []Field{
			{Tag: "GID", Kind: 0, Value: int64(65536)},
			{Tag: "REAS", Kind: 0, Value: int64(3)},
		},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := destroyGameReply(request)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 4 || command != 2 || messageType != 1 || correlation != 33 {
		t.Fatalf("destroy reply = %d/%d type %d correlation %d, want 4/2 type 1 correlation 33",
			component, command, messageType, correlation)
	}
	packet, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	gameID, err := integerField(packet.Fields, "GID")
	if err != nil || gameID != 65536 {
		t.Fatalf("destroy reply GID = %d, error %v; want 65536", gameID, err)
	}
	if len(packet.Fields) != 1 {
		t.Fatalf("destroy reply fields = %#v; want only GID", packet.Fields)
	}
}

func TestBlazeReplayReusesUserSettingsNotFoundForDifferentKey(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	latest := -1
	for index, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component == 9 && command == 10 {
			latest = index
		}
	}
	if latest < 0 {
		t.Fatal("replay corpus lacks UserSettingsLoad")
	}
	requestPacket, err := decodePacket(server.corpus[latest].request)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fieldAt(requestPacket.Fields, "KEY", 1)
	if err != nil {
		t.Fatal(err)
	}
	key.Value = []byte("DIFFERENT_SETTING")
	request, err := requestPacket.Encode()
	if err != nil {
		t.Fatal(err)
	}
	setBlazeCorrelation(request, 25)
	index, exact, reused := server.findReplay(request, len(server.corpus))
	if index != latest || exact || !reused {
		t.Fatalf("findReplay = (%d, %t, %t), want (%d, false, true)", index, exact, reused, latest)
	}
	reply := append([]byte(nil), server.corpus[index].replies[0]...)
	setBlazeCorrelation(reply, 25)
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 9 || command != 10 || messageType != 3 || correlation != 25 {
		t.Fatalf("reply metadata = %d/%d type %d correlation %d, want 9/10 type 3 correlation 25",
			component, command, messageType, correlation)
	}
}

func TestUtilTelemetryReplyEchoesTextAndClearsDirtyFlag(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	var request, capturedReply []byte
	for _, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component == 9 && command == 20 {
			request = append([]byte(nil), entry.request...)
			capturedReply = append([]byte(nil), entry.replies[0]...)
			break
		}
	}
	if request == nil {
		t.Fatal("replay corpus lacks Util telemetry request")
	}
	generated, err := utilTelemetryReply(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, capturedReply) {
		t.Fatalf("generated captured response differs: got %x, want %x", generated, capturedReply)
	}

	packet, err := decodePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	telemetryField, err := fieldAt(packet.Fields, "TLST", 4)
	if err != nil {
		t.Fatal(err)
	}
	telemetry := telemetryField.Value.(List)
	fields := telemetry.Items[0].([]Field)
	textField, err := fieldAt(fields, "UTXT", 1)
	if err != nil {
		t.Fatal(err)
	}
	textField.Value = []byte("REMOTE")
	telemetry.Items[0] = fields
	telemetryField.Value = telemetry
	request, err = packet.Encode()
	if err != nil {
		t.Fatal(err)
	}
	setBlazeCorrelation(request, 41)
	generated, err = utilTelemetryReply(request)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(generated)
	if component != 9 || command != 20 || messageType != 1 || correlation != 41 {
		t.Fatalf("reply metadata = %d/%d type %d correlation %d, want 9/20 type 1 correlation 41",
			component, command, messageType, correlation)
	}
	response, err := decodePacket(generated)
	if err != nil {
		t.Fatal(err)
	}
	responseListField, err := fieldAt(response.Fields, "TLST", 4)
	if err != nil {
		t.Fatal(err)
	}
	responseFields := responseListField.Value.(List).Items[0].([]Field)
	dirty, err := integerField(responseFields, "DIRT")
	if err != nil || dirty != 0 {
		t.Fatalf("response DIRT = %d, %v; want 0", dirty, err)
	}
	responseText, err := fieldAt(responseFields, "UTXT", 1)
	if err != nil {
		t.Fatal(err)
	}
	responseTextBytes, ok := responseText.Value.([]byte)
	if !ok || !bytes.Equal(responseTextBytes, []byte("REMOTE")) {
		t.Fatalf("response UTXT = %#v; want REMOTE", responseText)
	}
}

func TestNFS13UtilityPingIsSingleCorrelatedCurrentTimeReply(t *testing.T) {
	request, err := hex.DecodeString("00000009000200000000001d")
	if err != nil {
		t.Fatal(err)
	}
	const now = int64(1792638845)
	reply, err := utilPingReply(request, now)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 9 || command != 2 || messageType != 1 || correlation != 29 {
		t.Fatalf("reply metadata = %d/%d type %d correlation %d, want 9/2 type 1 correlation 29",
			component, command, messageType, correlation)
	}
	packet, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	serverTime, err := integerField(packet.Fields, "STIM")
	if err != nil {
		t.Fatal(err)
	}
	if serverTime != now {
		t.Fatalf("STIM = %d, want %d", serverTime, now)
	}
}

func TestReplayRefreshesAuthenticationAndHeartbeatTimes(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	const now = int64(1900000000)
	for _, test := range []struct {
		entry int
		want  int
	}{{entry: 1, want: 1}, {entry: 2, want: 2}} {
		updated, count, err := prepareReplayReply(server.corpus[test.entry].replies[0], now)
		if err != nil {
			t.Fatal(err)
		}
		if count != test.want {
			t.Fatalf("entry %d refreshed %d fields, want %d", test.entry, count, test.want)
		}
		packet, err := decodePacket(updated)
		if err != nil {
			t.Fatal(err)
		}
		assertReplayTimes(t, packet.Fields, now)
	}
}

func TestAuthenticationReplayRoundTripsByteExactly(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(server.corpus[2].replies); got != 4 {
		t.Fatalf("authentication reply bundle has %d frames, want 4", got)
	}
	want := [][3]uint16{
		{0x7802, 8, 2},
		{1, 152, 1},
		{0x7802, 2, 2},
		{0x7802, 5, 2},
	}
	for index, frame := range server.corpus[2].replies {
		component, command, messageType, _ := blazeMetadata(frame)
		if component != want[index][0] || command != want[index][1] ||
			uint16(messageType) != want[index][2] {
			t.Fatalf("authentication frame %d = %04x/%d type %d, want %04x/%d type %d",
				index, component, command, messageType,
				want[index][0], want[index][1], want[index][2])
		}
	}
	original := server.corpus[2].replies[1]
	packet, err := decodePacket(original)
	if err != nil {
		t.Fatal(err)
	}
	var timestamp int64
	var inspect func([]Field)
	inspect = func(fields []Field) {
		for _, field := range fields {
			if field.Kind == 0 && (field.Tag == "LLOG" || field.Tag == "LAST") {
				value := field.Value.(int64)
				if timestamp != 0 && timestamp != value {
					t.Fatalf("authentication timestamps differ: %d and %d", timestamp, value)
				}
				timestamp = value
			}
			if nested, ok := field.Value.([]Field); ok {
				inspect(nested)
			}
		}
	}
	inspect(packet.Fields)
	encoded, refreshed, err := prepareReplayReply(original, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed != 2 || !bytes.Equal(encoded, original) {
		t.Fatalf("authentication reply is not byte-stable (refreshed=%d, original=%x encoded=%x)", refreshed, original, encoded)
	}
}

func TestAuthenticationCanBeRepeatedOnOneConnection(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	client, backend := net.Pipe()
	defer client.Close()
	go server.handle(backend)
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	request := server.corpus[2].request
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := client.Write(request); err != nil {
			t.Fatalf("authentication attempt %d write: %v", attempt+1, err)
		}
		for frameIndex, want := range [][3]uint16{
			{0x7802, 8, 2},
			{1, 152, 1},
			{0x7802, 2, 2},
			{0x7802, 5, 2},
		} {
			reply, err := readBlazeFrame(client)
			if err != nil {
				t.Fatalf("authentication attempt %d frame %d: %v", attempt+1, frameIndex, err)
			}
			component, command, messageType, _ := blazeMetadata(reply)
			if component != want[0] || command != want[1] || uint16(messageType) != want[2] {
				t.Fatalf("authentication attempt %d frame %d = %04x/%d type %d, want %04x/%d type %d",
					attempt+1, frameIndex, component, command, messageType,
					want[0], want[1], want[2])
			}
		}
	}
}

func TestNFS13UtilityConfigQueriesAreRepeatable(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	server.nfs13 = true
	client, backend := net.Pipe()
	defer client.Close()
	go server.handle(backend)
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	requests := []string{
		"0009000900010000000000028e6a64010455726c00",
		"000a000900010000000000038e6a64010547616d6500",
	}
	for index, encoded := range requests {
		request, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(request); err != nil {
			t.Fatalf("Utility config request %d write: %v", index, err)
		}
		reply, err := readBlazeFrame(client)
		if err != nil {
			t.Fatalf("Utility config request %d reply: %v", index, err)
		}
		component, command, messageType, correlation := blazeMetadata(reply)
		if component != 9 || command != 1 || messageType != 1 ||
			correlation != uint32(index+2) {
			t.Fatalf("Utility config reply %d = len %d %d/%d type %d correlation %d",
				index, len(reply), component, command, messageType, correlation)
		}
		packet, err := decodePacket(reply)
		if err != nil {
			t.Fatalf("Utility config reply %d decode: %v", index, err)
		}
		configField, err := fieldAt(packet.Fields, "CONF", 5)
		if err != nil {
			t.Fatalf("Utility config %d CONF: %v", index, err)
		}
		config, ok := configField.Value.(MapValue)
		if !ok || config.KeyKind != 1 || config.ValueKind != 1 {
			t.Fatalf("Utility config %d CONF = %#v", index, configField.Value)
		}
		got := make(map[string]string)
		for _, pair := range config.Pairs {
			got[string(pair.Key.([]byte))] = string(pair.Value.([]byte))
		}
		wantConfig := map[string]string{
			"autolog_host":           "http://192.168.4.199:48386",
			"autolog_host_secure":    "http://192.168.4.199:48386",
			"server_manifest":        "nfs13/server-manifest",
			"server_manifest_secure": "nfs13/server-manifest",
			"layout_bundles":         "nfs13/layout-bundles",
			"layout_bundles_secure":  "nfs13/layout-bundles",
			"lua_bundles":            "nfs13/lua-bundles",
			"lua_bundles_secure":     "nfs13/lua-bundles",
		}
		if index == 1 {
			wantConfig = map[string]string{
				"realtime_presence_active":                 "1",
				"realtime_presence_client_timeout_seconds": "86400",
				"request_friend_presence_updates_enabled":  "0",
			}
		}
		for key, want := range wantConfig {
			if got[key] != want {
				t.Fatalf("Utility config %d %s = %q, want %q", index, key, got[key], want)
			}
		}
	}
}

func TestNFS13UtilityPostAuthResponseIsRepeatable(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	client, backend := net.Pipe()
	defer client.Close()
	go server.handle(backend)
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	for attempt, correlation := range []byte{5, 19} {
		request, err := hex.DecodeString("000000090008000000000000")
		if err != nil {
			t.Fatal(err)
		}
		request[11] = correlation
		if _, err := client.Write(request); err != nil {
			t.Fatalf("Utility post-auth attempt %d write: %v", attempt+1, err)
		}
		reply, err := readBlazeFrame(client)
		if err != nil {
			t.Fatalf("Utility post-auth attempt %d reply: %v", attempt+1, err)
		}
		component, command, messageType, gotCorrelation := blazeMetadata(reply)
		if len(reply) != 871 || component != 9 || command != 8 || messageType != 1 ||
			gotCorrelation != uint32(correlation) {
			t.Fatalf("Utility post-auth reply %d = len %d %d/%d type %d correlation %d",
				attempt+1, len(reply), component, command, messageType, gotCorrelation)
		}
	}
}

func TestNFS13AssociationListsResponseIsRepeatable(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	client, backend := net.Pipe()
	defer client.Close()
	go server.handle(backend)
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// NFS13's request contains its full list descriptor, while the replay
	// corpus's older request contains only the list type and max result count.
	// The response contract is the same, so reconnect authentication must be
	// able to issue this payload again after the ordered cursor has passed it.
	const encoded = "003b0019000600000000000086ccf40403018afa64090000009ac9f30001b2990003b2eb40010100d39c25000100b2dcc00000c32a64000000b78ca300bfffffff1fbe6ca30000"
	for attempt, correlation := range []byte{8, 22} {
		request, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		request[11] = correlation
		if _, err := client.Write(request); err != nil {
			t.Fatalf("Association Lists attempt %d write: %v", attempt+1, err)
		}
		reply, err := readBlazeFrame(client)
		if err != nil {
			t.Fatalf("Association Lists attempt %d reply: %v", attempt+1, err)
		}
		component, command, messageType, gotCorrelation := blazeMetadata(reply)
		if len(reply) != 293 || component != 25 || command != 6 || messageType != 1 ||
			gotCorrelation != uint32(correlation) {
			t.Fatalf("Association Lists reply %d = len %d %d/%d type %d correlation %d",
				attempt+1, len(reply), component, command, messageType, gotCorrelation)
		}
	}
}

func TestNFS13AssociationListsResponseUsesAuthenticatedOwner(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	const encoded = "003b0019000600000000000086ccf40403018afa64090000009ac9f30001b2990003b2eb40010100d39c25000100b2dcc00000c32a64000000b78ca300bfffffff1fbe6ca30000"
	request, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	index, _, _ := server.findReplay(request, 0)
	if index < 0 || len(server.corpus[index].replies) != 1 {
		t.Fatalf("Association Lists replay = index %d, replies %d", index, len(server.corpus[index].replies))
	}
	identity := &blazeIdentity{name: "player", id: 100}
	reply, _, err := personalizeReplayReply(server.corpus[index].replies[0], time.Now().Unix(), identity)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	lists, err := listField(packet.Fields, "LMAP")
	if err != nil || len(lists.Items) == 0 {
		t.Fatalf("LMAP = %#v, err=%v", lists, err)
	}
	for listIndex, item := range lists.Items {
		listFields, err := fieldsFromItem(item)
		if err != nil {
			t.Fatalf("LMAP[%d]: %v", listIndex, err)
		}
		info, err := structField(listFields, "INFO")
		if err != nil {
			t.Fatalf("LMAP[%d]: %v", listIndex, err)
		}
		ownerField, err := fieldAt(info, "BOID", 9)
		if err != nil {
			t.Fatalf("LMAP[%d]: %v", listIndex, err)
		}
		owner, ok := ownerField.Value.(ObjectID)
		if !ok || len(owner) == 0 || owner[len(owner)-1] != identity.id {
			t.Fatalf("LMAP[%d].INFO.BOID = %#v, want owner %d", listIndex, ownerField.Value, identity.id)
		}
	}
}

func TestNFS13AssociationListsReplyReturnsSubscribedFriendList(t *testing.T) {
	const encoded = "003b0019000600000000001686ccf40403018afa64090000009ac9f30001b2990003b2eb40010100d39c25000100b2dcc00000c32a64000000b78ca300bfffffff1fbe6ca30000"
	request, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := nfs13AssociationListsReply(request, &blazeIdentity{name: "player", id: 100})
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 25 || command != 6 || messageType != 1 || correlation != 22 {
		t.Fatalf("reply metadata = %d/%d type %d correlation %d", component, command, messageType, correlation)
	}
	packet, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	lists, err := listField(packet.Fields, "LMAP")
	if err != nil || lists.Kind != 3 || len(lists.Items) != 1 {
		t.Fatalf("LMAP = %#v, err=%v", lists, err)
	}
	listMembers, err := fieldsFromItem(lists.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	info, err := structField(listMembers, "INFO")
	if err != nil {
		t.Fatal(err)
	}
	ownerField, err := fieldAt(info, "BOID", 9)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := ownerField.Value.(ObjectID)
	if !ok || len(owner) != 3 || owner[0] != 25 || owner[1] != 1 || owner[2] != 100 {
		t.Fatalf("INFO.BOID = %#v, want [25 1 100]", ownerField.Value)
	}
	flags, err := integerField(info, "FLGS")
	if err != nil || flags != 1 {
		t.Fatalf("INFO.FLGS = %d, err=%v; want subscribed (1)", flags, err)
	}
	listID, err := structField(info, "LID")
	if err != nil {
		t.Fatal(err)
	}
	name, err := bytesField(listID, "LNM")
	if err != nil || string(name) != "friendList" {
		t.Fatalf("INFO.LID.LNM = %q, err=%v", name, err)
	}
	listType, err := integerField(listID, "TYPE")
	if err != nil || listType != 1 {
		t.Fatalf("INFO.LID.TYPE = %d, err=%v", listType, err)
	}
	members, err := listField(listMembers, "MEML")
	if err != nil || members.Kind != 3 || len(members.Items) != 0 {
		t.Fatalf("MEML = %#v, err=%v; want an empty struct list", members, err)
	}
	for _, tag := range []string{"OFRC", "TOCT"} {
		value, fieldErr := integerField(listMembers, tag)
		if fieldErr != nil || value != 0 {
			t.Fatalf("%s = %d, err=%v; want 0", tag, value, fieldErr)
		}
	}
}

func TestNFS13PlaygroupJoinNotificationCreatesSoloPrivateGroup(t *testing.T) {
	endpoint := func() []Field {
		return []Field{
			{Tag: "IP", Kind: 0, Value: int64(0xc0a804c7)},
			{Tag: "PORT", Kind: 0, Value: int64(20100)},
		}
	}
	address := &Union{Index: 2, Field: &Field{Tag: "VALU", Kind: 3, Value: []Field{
		{Tag: "EXIP", Kind: 3, Value: endpoint()},
		{Tag: "INIP", Kind: 3, Value: endpoint()},
	}}}
	notification, err := nfs13PlaygroupJoinNotification(
		&blazeIdentity{name: "player", id: 100}, address)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(notification)
	if component != 6 || command != 51 || messageType != 2 || correlation != 0 {
		t.Fatalf("notification metadata = %d/%d type %d correlation %d", component, command, messageType, correlation)
	}
	packet, err := decodePacket(notification)
	if err != nil {
		t.Fatal(err)
	}
	info, err := structField(packet.Fields, "INFO")
	if err != nil {
		t.Fatal(err)
	}
	for tag, want := range map[string]int64{
		"JOIN": 0, "MLIM": 8, "NTOP": 130, "OWNR": 100,
		"PGID": 1, "PRES": 2, "UPRS": 1, "VOIP": 0,
	} {
		got, fieldErr := integerField(info, tag)
		if fieldErr != nil || got != want {
			t.Fatalf("INFO.%s = %d, err=%v; want %d", tag, got, fieldErr, want)
		}
	}
	members, err := listField(packet.Fields, "MLST")
	if err != nil || members.Kind != 3 || len(members.Items) != 1 {
		t.Fatalf("MLST = %#v, err=%v", members, err)
	}
	member, err := fieldsFromItem(members.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := integerField(member, "PERM")
	if err != nil || permissions != 31 {
		t.Fatalf("MLST[0].PERM = %d, err=%v; want 31", permissions, err)
	}
	user, err := structField(member, "USER")
	if err != nil {
		t.Fatal(err)
	}
	id, err := integerField(user, "ID")
	if err != nil || id != 100 {
		t.Fatalf("MLST[0].USER.ID = %d, err=%v; want 100", id, err)
	}
	joining, err := integerField(packet.Fields, "USER")
	if err != nil || joining != 100 {
		t.Fatalf("USER = %d, err=%v; want 100", joining, err)
	}
}

func TestNFS13CreatePlaygroupReplyBuildsJoinResponse(t *testing.T) {
	endpoint := func() []Field {
		return []Field{
			{Tag: "IP", Kind: 0, Value: int64(0xc0a804c7)},
			{Tag: "PORT", Kind: 0, Value: int64(20100)},
		}
	}
	address := &Union{Index: 2, Field: &Field{Tag: "VALU", Kind: 3, Value: []Field{
		{Tag: "EXIP", Kind: 3, Value: endpoint()},
		{Tag: "INIP", Kind: 3, Value: endpoint()},
	}}}
	request := []byte{0, 0, 0, 6, 0, 1, 0, 0, 0, 0, 0, 42}
	reply, err := nfs13CreatePlaygroupReply(
		request, &blazeIdentity{name: "player", id: 100}, address)
	if err != nil {
		t.Fatal(err)
	}
	component, command, messageType, correlation := blazeMetadata(reply)
	if component != 6 || command != 1 || messageType != 1 || correlation != 42 {
		t.Fatalf("reply metadata = %d/%d type %d correlation %d", component, command, messageType, correlation)
	}
	packet, err := decodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	info, err := structField(packet.Fields, "INFO")
	if err != nil {
		t.Fatal(err)
	}
	playgroupID, err := integerField(info, "PGID")
	if err != nil || playgroupID != 1 {
		t.Fatalf("INFO.PGID = %d, err=%v; want 1", playgroupID, err)
	}
	members, err := listField(packet.Fields, "MLST")
	if err != nil || members.Kind != 3 || len(members.Items) != 1 {
		t.Fatalf("MLST = %#v, err=%v", members, err)
	}
	if _, err := fieldAt(packet.Fields, "USER", 0); err == nil {
		t.Fatal("CreatePlaygroup response unexpectedly contains notification-only USER")
	}
}

func TestNFS13AuthenticationLifecycleRequestsAreRepeatable(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	client, backend := net.Pipe()
	defer client.Close()
	go server.handle(backend)
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	requests := []struct {
		encoded     string
		command     uint16
		correlation uint32
	}{
		{"00050001010400000000000ed69bf0067f", 260, 14},
		{"000000010046000000000011", 70, 17},
		{"0028000100200000000000218b5a640000970cee0000970cfa00329ac86700039eeb33040101084e46533133504300beeb390000", 32, 33},
	}
	for _, test := range requests {
		request, err := hex.DecodeString(test.encoded)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(request); err != nil {
			t.Fatalf("Authentication command %d write: %v", test.command, err)
		}
		reply, err := readBlazeFrame(client)
		if err != nil {
			t.Fatalf("Authentication command %d reply: %v", test.command, err)
		}
		component, command, messageType, correlation := blazeMetadata(reply)
		if len(reply) != 12 || component != 1 || command != test.command ||
			messageType != 1 || correlation != test.correlation {
			t.Fatalf("Authentication lifecycle reply = len %d %d/%d type %d correlation %d",
				len(reply), component, command, messageType, correlation)
		}
	}
}

func TestLocalIdentityPersonalizesAuthentication(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	requestPacket, err := decodePacket(server.corpus[2].request)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := fieldAt(requestPacket.Fields, "AUTH", 1)
	if err != nil {
		t.Fatal(err)
	}
	auth.Value = []byte("ZLOCAL1:61736466")
	request, err := requestPacket.Encode()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := localBlazeIdentity(request)
	if err != nil {
		t.Fatal(err)
	}
	if identity.name != "asdf" || identity.id == 2 ||
		identity.gamePort != gamePortForIdentity(identity.id) {
		t.Fatalf("identity = %#v", identity)
	}
	for index, captured := range server.corpus[2].replies {
		reply, _, personalizeErr := personalizeReplayReply(captured, time.Now().Unix(), identity)
		if personalizeErr != nil {
			t.Fatal(personalizeErr)
		}
		if bytes.Contains(reply, []byte("mxmstr")) || bytes.Contains(reply, []byte("WAHAHA_IMMA_ZLO_TOKEN")) {
			t.Fatalf("authentication reply %d retains captured identity: %x", index, reply)
		}
	}
}

func TestNFS13StatsRepliesUseRequestedGroupAndParseableKey(t *testing.T) {
	for _, test := range []struct {
		name, group, groupTag string
		request, reply        string
	}{
		{
			name: "group descriptor", group: "license_plate", groupTag: "NAME",
			request: "00130007000400000000001fba1b65010e6c6963656e73655f706c61746500",
			reply:   "009b0007000400001000001f8ee86d01094d6574614461746100925ce301094d6574614461746100974e700882e00301ba1b6501094d6574614461746100cf48740403018e1d2701094d6574614461746100926b340109302e303030303030009b2b740103257300b24ce3010e5361766554696d657374616d7000ba1b65010e5361766554696d657374616d7000ce4ce3010e5361766554696d657374616d7000d39c25000200",
		},
		{
			name: "update notification", group: "license_plate_unlock", groupTag: "GRNM",
			request: "0050000700100000000000208679f20000969900040001a401af3d6d050100010e6c6963656e73655f706c6174650000ba1b6501094d6574614461746100c23d320001c2f9a60000c32a640000c34e700000d29b650000da99000001",
			reply:   "0059000700320000200000009f2bad01094d6574614461746100ae5e4001114e6f5f53636f70655f446566696e656400b21cf4008aafeaad0dcf4cc003cf48740403019699000002974e700882e00301c2f9a60000cf48740401010230000000da99000001",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := hex.DecodeString(test.request)
			if err != nil {
				t.Fatal(err)
			}
			requestPacket, err := decodePacket(request)
			if err != nil {
				t.Fatal(err)
			}
			name, err := fieldAt(requestPacket.Fields, "NAME", 1)
			if err != nil {
				t.Fatal(err)
			}
			name.Value = []byte(test.group)
			request, err = requestPacket.Encode()
			if err != nil {
				t.Fatal(err)
			}
			reply, err := hex.DecodeString(test.reply)
			if err != nil {
				t.Fatal(err)
			}
			rewritten, err := nfs13StatsReply(request, reply)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := decodePacket(rewritten)
			if err != nil {
				t.Fatal(err)
			}
			gotGroup, err := bytesField(packet.Fields, test.groupTag)
			if err != nil || string(gotGroup) != test.group {
				t.Fatalf("%s = %q, error %v; want %q", test.groupTag, gotGroup, err, test.group)
			}
			statFields := packet.Fields
			if test.groupTag == "GRNM" {
				statFields, err = structField(packet.Fields, "STS")
				if err != nil {
					t.Fatal(err)
				}
			}
			stats, err := listField(statFields, "STAT")
			if err != nil {
				t.Fatalf("STAT = %#v, error %v", stats, err)
			}
			if test.groupTag == "GRNM" {
				key, keyErr := bytesField(packet.Fields, "KEY")
				if keyErr != nil || string(key) != "license_plate=0" {
					t.Fatalf("KEY = %q, error %v; want requested scoped key", key, keyErr)
				}
				if len(stats.Items) != 0 {
					t.Fatalf("STAT has %d rows; want an empty NFS13 result set", len(stats.Items))
				}
			} else {
				scopes, scopeErr := mapField(packet.Fields, "KSUM")
				if scopeErr != nil || scopes.KeyKind != 1 || scopes.ValueKind != 0 || len(scopes.Pairs) != 1 ||
					string(scopes.Pairs[0].Key.([]byte)) != "license_plate" || scopes.Pairs[0].Value.(int64) != 0 {
					t.Fatalf("KSUM = %#v, error %v; want license_plate=0", scopes, scopeErr)
				}
				if len(stats.Items) == 0 {
					t.Fatal("group descriptor lost its compatibility scaffold")
				}
			}
		})
	}
}

func TestNFS13StatsUpdateDefaultsOmittedPlateScope(t *testing.T) {
	// This is the PC DVD 1.0 request emitted after the rewritten descriptor.
	// Unlike newer clients, it omits KSUM entirely.
	request, err := hex.DecodeString("003e0007001000000000001e8679f20000969900040001a401ba1b65010e6c6963656e73655f706c61746500c23d320001c2f9a60000c32a640000c34e700000d29b650000da99000001")
	if err != nil {
		t.Fatal(err)
	}
	reply, err := hex.DecodeString("0059000700320000200000009f2bad01094d6574614461746100ae5e4001114e6f5f53636f70655f446566696e656400b21cf4008aafeaad0dcf4cc003cf48740403019699000002974e700882e00301c2f9a60000cf48740401010230000000da99000001")
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := nfs13StatsReply(request, reply)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := decodePacket(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	key, err := bytesField(packet.Fields, "KEY")
	if err != nil || string(key) != "license_plate=0" {
		t.Fatalf("KEY = %q, error %v; want defaulted plate scope", key, err)
	}
	status, err := structField(packet.Fields, "STS")
	if err != nil {
		t.Fatal(err)
	}
	stats, err := listField(status, "STAT")
	if err != nil || len(stats.Items) != 0 {
		t.Fatalf("STAT = %#v, error %v; want an empty result set", stats, err)
	}
}

func TestNFS13LegacyTokenUsesConfiguredLSXIdentity(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	server.nfs13 = true
	server.legacyEAID = "player"
	server.legacyAccount = 100

	identity, err := server.blazeIdentity(server.corpus[2].request)
	if err != nil {
		t.Fatal(err)
	}
	if identity.name != "player" || identity.id != 100 ||
		identity.gamePort != gamePortForIdentity(100) ||
		string(identity.token) != legacyZLOAuthToken {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestNFS13AuthenticationSessionNotificationsUseConfiguredIdentity(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	server.nfs13 = true
	server.legacyEAID = "player"
	server.legacyAccount = 100
	identity, err := server.blazeIdentity(server.corpus[2].request)
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, captured := range server.corpus[2].replies {
		reply, _, err := personalizeReplayReply(captured, time.Now().Unix(), identity)
		if err != nil {
			t.Fatal(err)
		}
		component, command, messageType, _ := blazeMetadata(reply)
		if component != 0x7802 || (command != 2 && command != 5) || messageType != 2 {
			continue
		}
		reply, err = personalizeNFS13UserSessionNotification(reply, identity)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := decodePacket(reply)
		if err != nil {
			t.Fatal(err)
		}
		if command == 5 {
			id, err := integerField(packet.Fields, "ID")
			if err != nil {
				t.Fatal(err)
			}
			if id != identity.id {
				t.Fatalf("UserSessions command %d ID = %d, want %d", command, id, identity.id)
			}
		} else {
			user, err := structField(packet.Fields, "USER")
			if err != nil {
				t.Fatal(err)
			}
			for _, tag := range []string{"ID", "ORIG"} {
				value, err := integerField(user, tag)
				if err != nil {
					t.Fatal(err)
				}
				if value != identity.id {
					t.Fatalf("UserSessions command 2 %s = %d, want %d", tag, value, identity.id)
				}
			}
			data, err := structField(packet.Fields, "DATA")
			if err != nil {
				t.Fatal(err)
			}
			users, err := listField(data, "ULST")
			if err != nil || len(users.Items) != 1 {
				t.Fatalf("UserSessions command 2 ULST = %#v, err=%v", users, err)
			}
			objectID, ok := users.Items[0].(ObjectID)
			if !ok || len(objectID) == 0 || objectID[len(objectID)-1] != identity.id {
				t.Fatalf("UserSessions command 2 ULST identity = %#v, want %d", users.Items[0], identity.id)
			}
		}
		checked++
	}
	if checked != 2 {
		t.Fatalf("checked %d NFS13 UserSessions identity notifications, want 2", checked)
	}
}

func TestNFS13PreAuthAdvertisesRequestedService(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	requestPacket, err := decodePacket(server.corpus[0].request)
	if err != nil {
		t.Fatal(err)
	}
	clientData, err := structField(requestPacket.Fields, "CDAT")
	if err != nil {
		t.Fatal(err)
	}
	serviceField, err := fieldAt(clientData, "SVCN", 1)
	if err != nil {
		t.Fatal(err)
	}
	serviceField.Value = []byte("nfs-2013-pc")
	request, err := requestPacket.Encode()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := nfs13PreAuthReply(request, server.corpus[0].replies[0], "192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(reply, []byte("nfs-2013-pc")) ||
		!bytes.Contains(reply, []byte("NFS13-PC-Server")) {
		t.Fatalf("pre-auth reply lacks NFS13 service identity: %x", reply)
	}
	if bytes.Contains(reply, []byte("nfs-rivals-pc")) ||
		bytes.Contains(reply, []byte("NFS14-Rivals-PC-Server")) {
		t.Fatalf("pre-auth reply retains NFS14 service identity: %x", reply)
	}
	for _, expected := range [][]byte{
		[]byte("autolog_host"), []byte("autolog_host_secure"),
		[]byte("server_manifest"), []byte("server_manifest_secure"),
		[]byte("http://192.168.4.199:48386"),
	} {
		if !bytes.Contains(reply, expected) {
			t.Fatalf("pre-auth reply lacks NFS13 setting %q", expected)
		}
	}
	if _, err := decodePacket(reply); err != nil {
		t.Fatalf("rewritten pre-auth reply is invalid: %v", err)
	}
}

func TestLocalIdentityPersonalizesSetupTransportIdentifiers(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	var captured []byte
	for _, entry := range server.corpus {
		for _, reply := range entry.replies {
			component, command, messageType, _ := blazeMetadata(reply)
			if component == 4 && command == 20 && messageType == 2 {
				captured = reply
				break
			}
		}
		if captured != nil {
			break
		}
	}
	if captured == nil {
		t.Fatal("replay corpus lacks matchmaking setup notification")
	}
	type identifiers struct {
		admin, hostSession, originalHost int64
		machine, userGroup               int64
		gameUUID, playerUUID             string
	}
	read := func(identity *blazeIdentity) identifiers {
		t.Helper()
		raw, _, personalizeErr := personalizeReplayReply(
			captured, time.Now().Unix(), identity)
		if personalizeErr != nil {
			t.Fatal(personalizeErr)
		}
		packet, decodeErr := decodePacket(raw)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		game, _ := structField(packet.Fields, "GAME")
		admins, _ := listField(game, "ADMN")
		hostSession, _ := integerField(game, "HSES")
		originalHost, _ := integerField(game, "OGHI")
		gameUUIDField, _ := fieldAt(game, "UUID", 1)
		roster, _ := listField(packet.Fields, "PROS")
		player, _ := fieldsFromItem(roster.Items[0])
		playerUUIDField, _ := fieldAt(player, "UUID", 1)
		playerNetwork, _ := unionField(player, "PNET")
		pair := playerNetwork.Field.Value.([]Field)
		machine, _ := integerField(pair, "MACI")
		userGroupField, _ := fieldAt(player, "UGID", 9)
		userGroup := userGroupField.Value.(ObjectID)
		return identifiers{
			admin:        admins.Items[0].(int64),
			hostSession:  hostSession,
			originalHost: originalHost,
			machine:      machine,
			userGroup:    userGroup[len(userGroup)-1],
			gameUUID:     string(gameUUIDField.Value.([]byte)),
			playerUUID:   string(playerUUIDField.Value.([]byte)),
		}
	}
	firstIdentity := &blazeIdentity{name: "first", token: []byte("first"), id: 1001}
	secondIdentity := &blazeIdentity{name: "second", token: []byte("second"), id: 1002}
	first := read(firstIdentity)
	second := read(secondIdentity)
	if first.admin != firstIdentity.id || first.hostSession != firstIdentity.id ||
		first.originalHost != firstIdentity.id ||
		first.userGroup != firstIdentity.id {
		t.Fatalf("first identifiers = %#v; want identity %d", first, firstIdentity.id)
	}
	if second.admin != secondIdentity.id || second.hostSession != secondIdentity.id ||
		second.originalHost != secondIdentity.id ||
		second.userGroup != secondIdentity.id {
		t.Fatalf("second identifiers = %#v; want identity %d", second, secondIdentity.id)
	}
	if first.gameUUID == second.gameUUID || first.playerUUID == second.playerUUID ||
		first.gameUUID == first.playerUUID || second.gameUUID == second.playerUUID {
		t.Fatalf("UUIDs are not unique: first=%#v second=%#v", first, second)
	}
	if first.machine == 0 || first.machine != second.machine {
		t.Fatalf("captured local MACI must remain client-owned: first=%d second=%d",
			first.machine, second.machine)
	}
}

func TestLocalIdentityPortRewritesBothAdvertisedEndpoints(t *testing.T) {
	address := &Union{Index: 2, Field: &Field{
		Tag: "VALU", Kind: 3,
		Value: []Field{
			{Tag: "EXIP", Kind: 3, Value: []Field{
				{Tag: "IP", Kind: 0, Value: int64(0xc0a804c7)},
				{Tag: "PORT", Kind: 0, Value: int64(3659)},
			}},
			{Tag: "INIP", Kind: 3, Value: []Field{
				{Tag: "IP", Kind: 0, Value: int64(0xc0a804c7)},
				{Tag: "PORT", Kind: 0, Value: int64(3659)},
			}},
			{Tag: "MACI", Kind: 0, Value: int64(1240227046)},
		},
	}}
	const port = int64(38058)
	if err := rewriteNetworkPort(address, port); err != nil {
		t.Fatal(err)
	}
	const ip = int64(0xc61294aa)
	if err := rewriteNetworkIP(address, ip); err != nil {
		t.Fatal(err)
	}
	pair := address.Field.Value.([]Field)
	for _, tag := range []string{"INIP", "EXIP"} {
		endpoint, err := structField(pair, tag)
		if err != nil {
			t.Fatal(err)
		}
		got, err := integerField(endpoint, "PORT")
		if err != nil || got != port {
			t.Fatalf("%s port = %d, error %v; want %d", tag, got, err, port)
		}
		gotIP, err := integerField(endpoint, "IP")
		if err != nil || gotIP != ip {
			t.Fatalf("%s IP = %#x, error %v; want %#x", tag, gotIP, err, ip)
		}
	}
	gotMachineID, err := integerField(pair, "MACI")
	if err != nil || gotMachineID != 1240227046 {
		t.Fatalf("MACI = %d, error %v; want client value 1240227046",
			gotMachineID, err)
	}
}

func TestDirectBlazeSetupsShareRegistryLobby(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	var captured []byte
	for _, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component == 4 && command == 13 {
			for _, reply := range entry.replies {
				rComponent, rCommand, rType, _ := blazeMetadata(reply)
				if rComponent == 4 && rCommand == 20 && rType == 2 {
					captured = reply
				}
			}
			break
		}
	}
	if captured == nil {
		t.Fatal("replay corpus lacks matchmaking setup notification")
	}
	registry := newRegistry(time.Minute, false, false)
	first := &blazeIdentity{name: "first", token: []byte("first"), id: 1001}
	second := &blazeIdentity{name: "second", token: []byte("second"), id: 1002}
	firstSetup, _, err := personalizeReplayReply(captured, time.Now().Unix(), first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.exchange("blaze:first", firstSetup); err != nil {
		t.Fatal(err)
	}
	secondSetup, _, err := personalizeReplayReply(captured, time.Now().Unix(), second)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := registry.exchange("blaze:second", secondSetup)
	if err != nil {
		t.Fatal(err)
	}
	joinedPacket, err := decodePacket(joined)
	if err != nil {
		t.Fatal(err)
	}
	roster, err := listField(joinedPacket.Fields, "PROS")
	if err != nil || len(roster.Items) != 2 {
		t.Fatalf("joined roster has %d players, error %v; want 2", len(roster.Items), err)
	}
	events := registry.drain("blaze:first")
	if len(events) != 1 {
		t.Fatalf("host received %d join notifications, want 1", len(events))
	}
	component, command, messageType, _ := blazeMetadata(events[0])
	if component != 4 || command != 21 || messageType != 2 {
		t.Fatalf("host notification = %d/%d type %d, want 4/21 type 2", component, command, messageType)
	}
	meshRequest, err := (Packet{
		Header: []byte{0, 0, 0, 4, 0, 29, 0, 0, 0, 0, 0, 0},
		Fields: []Field{
			{Tag: "GID", Kind: 0, Value: registry.gameID("blaze:first")},
			{Tag: "STAT", Kind: 0, Value: int64(2)},
			{Tag: "TCG", Kind: 9, Value: ObjectID{4, 1, second.id}},
		},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = registry.updateMesh("blaze:first", meshRequest); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"blaze:first", "blaze:second"} {
		meshEvents := registry.drain(key)
		if len(meshEvents) != 2 {
			t.Fatalf("%s received %d mesh notifications, want 2", key, len(meshEvents))
		}
		component, command, messageType, _ = blazeMetadata(meshEvents[0])
		if component != 4 || command != 116 || messageType != 2 {
			t.Fatalf("mesh-state notification = %d/%d type %d, want 4/116 type 2", component, command, messageType)
		}
		component, command, messageType, _ = blazeMetadata(meshEvents[1])
		if component != 4 || command != 30 || messageType != 2 {
			t.Fatalf("mesh-complete notification = %d/%d type %d, want 4/30 type 2", component, command, messageType)
		}
		meshPacket, decodeErr := decodePacket(meshEvents[1])
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		pid, pidErr := integerField(meshPacket.Fields, "PID")
		if pidErr != nil || pid != second.id {
			t.Fatalf("mesh completion PID = %d, error %v; want %d", pid, pidErr, second.id)
		}
	}
	var capturedState []byte
	for _, entry := range server.corpus {
		component, command, _, _ := blazeMetadata(entry.request)
		if component == 4 && command == 3 && len(entry.replies) == 2 {
			capturedState = entry.replies[1]
			break
		}
	}
	state, _, err := personalizeReplayReply(capturedState, time.Now().Unix(), first)
	if err != nil {
		t.Fatal(err)
	}
	state, err = setNotificationGameID(state, registry.gameID("blaze:first"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.exchange("blaze:first", state); err != nil {
		t.Fatal(err)
	}
	events = registry.drain("blaze:second")
	if len(events) != 1 {
		t.Fatalf("joiner received %d state notifications, want 1", len(events))
	}
	component, command, messageType, _ = blazeMetadata(events[0])
	if component != 4 || command != 100 || messageType != 2 {
		t.Fatalf("state notification = %d/%d type %d, want 4/100 type 2", component, command, messageType)
	}
}

func assertReplayTimes(t *testing.T, fields []Field, now int64) {
	t.Helper()
	for _, field := range fields {
		if field.Kind == 0 && (field.Tag == "STIM" || field.Tag == "LLOG" || field.Tag == "LAST") {
			if field.Value != now {
				t.Errorf("%s = %v, want %d", field.Tag, field.Value, now)
			}
		}
		if nested, ok := field.Value.([]Field); ok {
			assertReplayTimes(t, nested, now)
		}
	}
}

func TestLegacyRedirectorTLS10Handshake(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tlsListener := tls.NewListener(listener, server.tlsConfig)
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			accepted <- acceptErr
			return
		}
		defer connection.Close()
		accepted <- connection.(*tls.Conn).Handshake()
	}()
	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestCapturedRedirectorTLS11Parameters(t *testing.T) {
	server, err := newBlazeServer("192.168.4.199")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tlsListener := tls.NewListener(listener, redirectorTLSConfig(server.tlsConfig))
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			accepted <- acceptErr
			return
		}
		defer connection.Close()
		accepted <- connection.(*tls.Conn).Handshake()
	}()
	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS11,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	_ = client.Close()
	if state.Version != tls.VersionTLS11 || state.CipherSuite != tls.TLS_RSA_WITH_AES_256_CBC_SHA {
		t.Fatalf("negotiated version=%#x cipher=%#x", state.Version, state.CipherSuite)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}
