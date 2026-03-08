// Copyright 2026 Davide Guerri <davide.guerri@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oast_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dguerri/oast-mcp/internal/oast"
)

const testZone = "oast.example.com"
const testPublicIP = "1.2.3.4"

const testTSIGKeyName = "caddy."
const testTSIGKeyHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func newTestNative(t *testing.T, sink oast.EventSink) (*oast.Native, int, int) {
	t.Helper()
	dnsPort := freeUDPPort(t)
	httpPort := freeTCPPort(t)
	n := oast.NewNative(testZone, testPublicIP, "127.0.0.1", "127.0.0.1", dnsPort, httpPort, "", "", "", sink, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		n.Stop()
	})
	require.NoError(t, n.StartPolling(ctx))
	return n, dnsPort, httpPort
}

func TestNative_NewSession_UniqueCorrelationIDs(t *testing.T) {
	sink := &testSink{}
	n, _, _ := newTestNative(t, sink)
	ctx := context.Background()

	ep1, err := n.NewSession(ctx, "sess-1", "alice")
	require.NoError(t, err)
	ep2, err := n.NewSession(ctx, "sess-2", "alice")
	require.NoError(t, err)

	assert.NotEqual(t, ep1.CorrelationID, ep2.CorrelationID)
	assert.Len(t, ep1.CorrelationID, oast.CorrIDBytes*2, "correlation ID must be CorrIDBytes*2 hex chars")
	assert.Contains(t, ep1.DNS, testZone)
	assert.Contains(t, ep1.HTTP, "http://")
	assert.Contains(t, ep1.HTTPS, "https://")
	assert.Equal(t, ep1.CorrelationID+"."+testZone, ep1.DNS)
}

func TestNative_DNS_ARecord_SavesEvent(t *testing.T) {
	sink := &testSink{}
	n, dnsPort, _ := newTestNative(t, sink)
	ctx := context.Background()

	ep, err := n.NewSession(ctx, "sess-1", "alice")
	require.NoError(t, err)

	// Send A query for the session's DNS endpoint
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(ep.DNS), dns.TypeA)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)

	// Check answer
	require.Len(t, resp.Answer, 1)
	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, testPublicIP, a.A.String())

	// Event must arrive synchronously (in-band)
	require.Eventually(t, func() bool { return sink.Len() == 1 }, time.Second, 10*time.Millisecond)
	assert.Equal(t, "dns", sink.Events()[0].Protocol)
	assert.Equal(t, "sess-1", sink.Events()[0].SessionID)
	assert.Equal(t, "alice", sink.Events()[0].TenantID)
}

func TestNative_DNS_UnknownCorrID_NoEvent(t *testing.T) {
	sink := &testSink{}
	_, dnsPort, _ := newTestNative(t, sink)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("unknowncorrid."+testZone), dns.TypeA)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)

	// Still returns the A record (authoritative), but no event
	require.Len(t, resp.Answer, 1)
	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, sink.Len())
}

func TestNative_HTTP_SavesEvent(t *testing.T) {
	sink := &testSink{}
	n, _, httpPort := newTestNative(t, sink)
	ctx := context.Background()

	ep, err := n.NewSession(ctx, "sess-2", "bob")
	require.NoError(t, err)

	// Send HTTP request with correct Host header
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/some/path", httpPort), nil)
	require.NoError(t, err)
	req.Host = ep.DNS // e.g. abc123.oast.example.com

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Eventually(t, func() bool { return sink.Len() == 1 }, time.Second, 10*time.Millisecond)
	assert.Equal(t, "http", sink.Events()[0].Protocol)
	assert.Equal(t, "sess-2", sink.Events()[0].SessionID)
	assert.Equal(t, "bob", sink.Events()[0].TenantID)
}

func TestNative_HTTP_UnknownHost_NoEvent(t *testing.T) {
	sink := &testSink{}
	_, _, httpPort := newTestNative(t, sink)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", httpPort), nil)
	require.NoError(t, err)
	req.Host = "notmyzone.example.com"

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, sink.Len())
}

func TestNative_StartStop_NoPanic(t *testing.T) {
	sink := &testSink{}
	_, _, _ = newTestNative(t, sink)
	// cleanup registered by newTestNative
}

func TestNative_DNS_SOA_ZoneApex(t *testing.T) {
	sink := &testSink{}
	n, dnsPort, _ := newTestNative(t, sink)
	ctx := context.Background()
	_, err := n.NewSession(ctx, "sess-soa", "alice")
	require.NoError(t, err)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(testZone), dns.TypeSOA)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)

	require.Len(t, resp.Answer, 1)
	soa, ok := resp.Answer[0].(*dns.SOA)
	require.True(t, ok)
	assert.Equal(t, dns.Fqdn(testZone), soa.Hdr.Name)
	assert.True(t, resp.Authoritative)
	assert.Zero(t, sink.Len(), "SOA query must not generate an event")
}

func TestNative_DNS_SOA_Subdomain(t *testing.T) {
	sink := &testSink{}
	_, dnsPort, _ := newTestNative(t, sink)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_acme-challenge."+testZone), dns.TypeSOA)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)

	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	assert.Empty(t, resp.Answer, "subdomain SOA must not go in Answer section")
	require.Len(t, resp.Ns, 1, "subdomain SOA must be in Authority section")
	soa, ok := resp.Ns[0].(*dns.SOA)
	require.True(t, ok)
	assert.Equal(t, dns.Fqdn(testZone), soa.Hdr.Name)
	assert.True(t, resp.Authoritative)
	assert.Zero(t, sink.Len())
}

func TestNative_DNS_TXT_AcmeChallenge(t *testing.T) {
	sink := &testSink{}
	n, dnsPort, _ := newTestNative(t, sink)

	// Manually inject a TXT record
	n.SetTXT("_acme-challenge."+testZone, "test-token-value")

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_acme-challenge."+testZone), dns.TypeTXT)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)

	require.Len(t, resp.Answer, 1)
	txt, ok := resp.Answer[0].(*dns.TXT)
	require.True(t, ok)
	require.Len(t, txt.Txt, 1)
	assert.Equal(t, "test-token-value", txt.Txt[0])
	assert.True(t, resp.Authoritative)
	assert.Zero(t, sink.Len(), "TXT query must not generate an event")
}

func TestNative_DNS_TXT_NotFound(t *testing.T) {
	sink := &testSink{}
	_, dnsPort, _ := newTestNative(t, sink)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_acme-challenge."+testZone), dns.TypeTXT)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)

	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	assert.Empty(t, resp.Answer)
	assert.True(t, resp.Authoritative)
}

func newTestNativeWithTSIG(t *testing.T, sink oast.EventSink) (*oast.Native, int, int) {
	t.Helper()
	dnsPort := freeUDPPort(t)
	httpPort := freeTCPPort(t)
	n := oast.NewNative(testZone, testPublicIP, "127.0.0.1", "127.0.0.1",
		dnsPort, httpPort, testTSIGKeyName, testTSIGKeyHex, "127.0.0.1", sink, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); n.Stop() })
	require.NoError(t, n.StartPolling(ctx))
	return n, dnsPort, httpPort
}

func tsigKeyB64(t *testing.T) string {
	t.Helper()
	b, err := hex.DecodeString(testTSIGKeyHex)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(b)
}

func sendUpdate(t *testing.T, port int, rrs []dns.RR, keyName, keySecret string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(testZone))
	var add, remove []dns.RR
	for _, rr := range rrs {
		if rr.Header().Class == dns.ClassNONE {
			remove = append(remove, rr)
		} else {
			add = append(add, rr)
		}
	}
	m.Insert(add)
	m.Remove(remove)
	if keyName != "" {
		m.SetTsig(keyName, dns.HmacSHA256, 300, time.Now().Unix())
	}
	c := new(dns.Client)
	if keyName != "" {
		c.TsigSecret = map[string]string{keyName: keySecret}
	}
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	return resp
}

func TestNative_RFC2136_AddTXT(t *testing.T) {
	sink := &testSink{}
	_, dnsPort, _ := newTestNativeWithTSIG(t, sink)
	keyB64 := tsigKeyB64(t)

	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn("_acme-challenge." + testZone),
			Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120,
		},
		Txt: []string{"letsencrypt-token"},
	}
	resp := sendUpdate(t, dnsPort, []dns.RR{rr}, testTSIGKeyName, keyB64)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	// Verify the record is now served
	c := new(dns.Client)
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn("_acme-challenge."+testZone), dns.TypeTXT)
	resp2, _, err := c.Exchange(q, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)
	require.Len(t, resp2.Answer, 1)
	assert.Equal(t, "letsencrypt-token", resp2.Answer[0].(*dns.TXT).Txt[0])
}

func TestNative_RFC2136_DeleteTXT(t *testing.T) {
	sink := &testSink{}
	n, dnsPort, _ := newTestNativeWithTSIG(t, sink)
	keyB64 := tsigKeyB64(t)
	n.SetTXT("_acme-challenge."+testZone, "to-be-deleted")

	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn("_acme-challenge." + testZone),
			Rrtype: dns.TypeTXT, Class: dns.ClassNONE, Ttl: 0,
		},
		Txt: []string{"to-be-deleted"},
	}
	resp := sendUpdate(t, dnsPort, []dns.RR{rr}, testTSIGKeyName, keyB64)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	c := new(dns.Client)
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn("_acme-challenge."+testZone), dns.TypeTXT)
	resp2, _, err := c.Exchange(q, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)
	assert.Empty(t, resp2.Answer)
}

func TestNative_RFC2136_DeleteTXT_WrongValue_Preserved(t *testing.T) {
	sink := &testSink{}
	n, dnsPort, _ := newTestNativeWithTSIG(t, sink)
	keyB64 := tsigKeyB64(t)
	n.SetTXT("_acme-challenge."+testZone, "production-token")

	// ClassNONE with wrong value: record must NOT be deleted
	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn("_acme-challenge." + testZone),
			Rrtype: dns.TypeTXT, Class: dns.ClassNONE, Ttl: 0,
		},
		Txt: []string{"staging-token"},
	}
	resp := sendUpdate(t, dnsPort, []dns.RR{rr}, testTSIGKeyName, keyB64)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	c := new(dns.Client)
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn("_acme-challenge."+testZone), dns.TypeTXT)
	resp2, _, err := c.Exchange(q, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)
	require.Len(t, resp2.Answer, 1, "record should not have been deleted by wrong-value ClassNONE")
	assert.Equal(t, "production-token", resp2.Answer[0].(*dns.TXT).Txt[0])
}

func TestNative_RFC2136_NoTSIG_Refused(t *testing.T) {
	sink := &testSink{}
	_, dnsPort, _ := newTestNativeWithTSIG(t, sink)

	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn("_acme-challenge." + testZone),
			Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120,
		},
		Txt: []string{"bad"},
	}
	resp := sendUpdate(t, dnsPort, []dns.RR{rr}, "", "")
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)
}

func TestNative_RFC2136_WrongKey_Refused(t *testing.T) {
	sink := &testSink{}
	_, dnsPort, _ := newTestNativeWithTSIG(t, sink)

	wrongKeyHex := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	b, _ := hex.DecodeString(wrongKeyHex)
	wrongKeyB64 := base64.StdEncoding.EncodeToString(b)

	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn("_acme-challenge." + testZone),
			Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120,
		},
		Txt: []string{"bad"},
	}
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(testZone))
	m.Insert([]dns.RR{rr})
	m.SetTsig(testTSIGKeyName, dns.HmacSHA256, 300, time.Now().Unix())
	c := new(dns.Client)
	c.TsigSecret = map[string]string{testTSIGKeyName: wrongKeyB64}
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeNotAuth, resp.Rcode)
}

func TestNative_RFC2136_NonAcmeTarget_Refused(t *testing.T) {
	sink := &testSink{}
	_, dnsPort, _ := newTestNativeWithTSIG(t, sink)
	keyB64 := tsigKeyB64(t)

	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn("evil." + testZone),
			Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60,
		},
		A: net.ParseIP("1.2.3.4"),
	}
	resp := sendUpdate(t, dnsPort, []dns.RR{rr}, testTSIGKeyName, keyB64)
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)
}

func TestNative_RFC2136_AllowedAddr_Accepted(t *testing.T) {
	// Allowed addr = "127.0.0.1"; test client sends from 127.0.0.1 → must succeed.
	sink := &testSink{}
	dnsPort := freeUDPPort(t)
	httpPort := freeTCPPort(t)
	n := oast.NewNative(testZone, testPublicIP, "127.0.0.1", "127.0.0.1",
		dnsPort, httpPort, testTSIGKeyName, testTSIGKeyHex, "127.0.0.1", sink, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); n.Stop() })
	require.NoError(t, n.StartPolling(ctx))

	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn("_acme-challenge." + testZone),
			Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120,
		},
		Txt: []string{"allowed-token"},
	}
	resp := sendUpdate(t, dnsPort, []dns.RR{rr}, testTSIGKeyName, tsigKeyB64(t))
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
}

func TestNative_DNS_NS_ZoneApex(t *testing.T) {
	sink := &testSink{}
	_, dnsPort, _ := newTestNative(t, sink)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(testZone), dns.TypeNS)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)

	require.Len(t, resp.Answer, 1)
	ns, ok := resp.Answer[0].(*dns.NS)
	require.True(t, ok)
	assert.Equal(t, "ns1."+dns.Fqdn(testZone), ns.Ns)
	assert.True(t, resp.Authoritative)
	assert.Zero(t, sink.Len(), "NS query must not generate an event")
}

func TestNative_RFC2136_TCP_AddTXT(t *testing.T) {
	// caddy-dns/rfc2136 sends RFC 2136 UPDATE over TCP — the server must accept TCP connections.
	sink := &testSink{}
	_, dnsPort, _ := newTestNativeWithTSIG(t, sink)
	keyB64 := tsigKeyB64(t)

	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn("_acme-challenge." + testZone),
			Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120,
		},
		Txt: []string{"tcp-acme-token"},
	}
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(testZone))
	m.Insert([]dns.RR{rr})
	m.SetTsig(testTSIGKeyName, dns.HmacSHA256, 300, time.Now().Unix())
	c := &dns.Client{
		Net:        "tcp",
		TsigSecret: map[string]string{testTSIGKeyName: keyB64},
	}
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
}

func TestNative_RFC2136_DisallowedAddr_Refused(t *testing.T) {
	// Allowed addr = "192.0.2.1"; test client sends from 127.0.0.1 → must be refused.
	sink := &testSink{}
	dnsPort := freeUDPPort(t)
	httpPort := freeTCPPort(t)
	n := oast.NewNative(testZone, testPublicIP, "127.0.0.1", "127.0.0.1",
		dnsPort, httpPort, testTSIGKeyName, testTSIGKeyHex, "192.0.2.1", sink, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); n.Stop() })
	require.NoError(t, n.StartPolling(ctx))

	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn("_acme-challenge." + testZone),
			Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120,
		},
		Txt: []string{"should-be-refused"},
	}
	resp := sendUpdate(t, dnsPort, []dns.RR{rr}, testTSIGKeyName, tsigKeyB64(t))
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)
}

// TestNative_HTTP_RichEvent verifies that a POST request's query string,
// headers, body, user-agent, and content-type are all captured in the event data.
func TestNative_HTTP_RichEvent(t *testing.T) {
	sink := &testSink{}
	n, _, httpPort := newTestNative(t, sink)
	ctx := context.Background()

	ep, err := n.NewSession(ctx, "sess-rich", "alice")
	require.NoError(t, err)

	body := strings.NewReader("hello=world&foo=bar")
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/probe?token=abc&x=1", httpPort),
		body,
	)
	require.NoError(t, err)
	req.Host = ep.DNS
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Custom-Header", "pentest-value")
	req.Header.Set("User-Agent", "TestAgent/1.0")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Eventually(t, func() bool { return sink.Len() == 1 }, time.Second, 10*time.Millisecond)

	data := sink.Events()[0].Data
	assert.Equal(t, "token=abc&x=1", data["query_string"])
	assert.Equal(t, "TestAgent/1.0", data["user_agent"])
	assert.Equal(t, "application/x-www-form-urlencoded", data["content_type"])
	assert.Equal(t, "hello=world&foo=bar", data["body"])
	assert.Equal(t, false, data["body_truncated"])

	headers, ok := data["headers"].(map[string]any)
	require.True(t, ok, "headers should be a map[string]any")
	assert.Contains(t, headers, "X-Custom-Header")
	assert.Equal(t, "pentest-value", headers["X-Custom-Header"])
}

// TestNative_DNS_LabelSuffix_SavesEvent verifies that a DNS A query to
// <corrID>-<label>.<zone> (the shape produced by oast_generate_payload with a label)
// is correctly attributed to the session.  This is the primary labelled-payload path
// and must work for both DNS and HTTP (wildcard TLS covers a single extra label).
func TestNative_DNS_LabelSuffix_SavesEvent(t *testing.T) {
	sink := &testSink{}
	n, dnsPort, _ := newTestNative(t, sink)
	ctx := context.Background()

	ep, err := n.NewSession(ctx, "sess-label-dns", "alice")
	require.NoError(t, err)

	labelledName := ep.CorrelationID + "-login-form." + testZone
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(labelledName), dns.TypeA)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)

	require.Len(t, resp.Answer, 1)
	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, testPublicIP, a.A.String())

	require.Eventually(t, func() bool { return sink.Len() == 1 }, time.Second, 10*time.Millisecond)
	ev := sink.Events()[0]
	assert.Equal(t, "dns", ev.Protocol)
	assert.Equal(t, "sess-label-dns", ev.SessionID)
	assert.Equal(t, strings.ToLower(labelledName), ev.Data["qname"])
}

// TestNative_HTTP_LabelSuffix_SavesEvent verifies that an HTTP request whose Host
// is <corrID>-<label>.<zone> is correctly attributed to the session.
func TestNative_HTTP_LabelSuffix_SavesEvent(t *testing.T) {
	sink := &testSink{}
	n, _, httpPort := newTestNative(t, sink)
	ctx := context.Background()

	ep, err := n.NewSession(ctx, "sess-label-http", "bob")
	require.NoError(t, err)

	labelledHost := ep.CorrelationID + "-ua-header." + testZone
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", httpPort), nil)
	require.NoError(t, err)
	req.Host = labelledHost

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Eventually(t, func() bool { return sink.Len() == 1 }, time.Second, 10*time.Millisecond)
	ev := sink.Events()[0]
	assert.Equal(t, "http", ev.Protocol)
	assert.Equal(t, "sess-label-http", ev.SessionID)
	assert.Equal(t, strings.ToLower(labelledHost), ev.Data["host"])
}

// TestNative_DNS_PrefixAndLabel_SavesEvent verifies the combined form:
// <prefix>.<corrID>-<label>.<zone> — multi-label prefix for DNS exfil AND a label.
func TestNative_DNS_PrefixAndLabel_SavesEvent(t *testing.T) {
	sink := &testSink{}
	n, dnsPort, _ := newTestNative(t, sink)
	ctx := context.Background()

	ep, err := n.NewSession(ctx, "sess-prefix-label", "charlie")
	require.NoError(t, err)

	combinedName := "exfil-chunk." + ep.CorrelationID + "-probe." + testZone
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(combinedName), dns.TypeA)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)

	require.Len(t, resp.Answer, 1)
	require.Eventually(t, func() bool { return sink.Len() == 1 }, time.Second, 10*time.Millisecond)
	ev := sink.Events()[0]
	assert.Equal(t, "sess-prefix-label", ev.SessionID)
	assert.Equal(t, strings.ToLower(combinedName), ev.Data["qname"])
}

// TestNative_DNS_SubdomainPrefix_SavesEvent verifies that a DNS A query to
// <prefix>.<corrID>.<zone> is attributed to the correct session and that the
// full qname (including the prefix) is recorded in the event data.
// This is the primary DNS-based data-exfiltration path: the caller encodes
// arbitrary data in the prefix labels and the server correlates via the
// rightmost label (the corrID).
func TestNative_DNS_SubdomainPrefix_SavesEvent(t *testing.T) {
	sink := &testSink{}
	n, dnsPort, _ := newTestNative(t, sink)
	ctx := context.Background()

	ep, err := n.NewSession(ctx, "sess-prefix-dns", "alice")
	require.NoError(t, err)

	// Query with an arbitrary prefix: exfil-data.<corrID>.<zone>
	prefixedName := "exfil-data." + ep.DNS
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(prefixedName), dns.TypeA)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)

	// Server must still return the A record
	require.Len(t, resp.Answer, 1)
	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, testPublicIP, a.A.String())

	// Event must be attributed to the correct session
	require.Eventually(t, func() bool { return sink.Len() == 1 }, time.Second, 10*time.Millisecond)
	ev := sink.Events()[0]
	assert.Equal(t, "dns", ev.Protocol)
	assert.Equal(t, "sess-prefix-dns", ev.SessionID)
	assert.Equal(t, "alice", ev.TenantID)

	// The full qname (including the exfiltration prefix) must be preserved
	assert.Equal(t, strings.ToLower(prefixedName), ev.Data["qname"])
}

// TestNative_DNS_MultiLabelPrefix_SavesEvent verifies that multiple prefix labels
// (e.g. chunk1.chunk2.<corrID>.<zone>) all resolve to the correct session.
func TestNative_DNS_MultiLabelPrefix_SavesEvent(t *testing.T) {
	sink := &testSink{}
	n, dnsPort, _ := newTestNative(t, sink)
	ctx := context.Background()

	ep, err := n.NewSession(ctx, "sess-multilabel", "bob")
	require.NoError(t, err)

	prefixedName := "aGVsbG8.d29ybGQ." + ep.DNS // two base64url-style chunks
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(prefixedName), dns.TypeA)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)

	require.Len(t, resp.Answer, 1)
	require.Eventually(t, func() bool { return sink.Len() == 1 }, time.Second, 10*time.Millisecond)
	ev := sink.Events()[0]
	assert.Equal(t, "sess-multilabel", ev.SessionID)
	assert.Equal(t, strings.ToLower(prefixedName), ev.Data["qname"])
}

// TestNative_HTTP_SubdomainPrefix_SavesEvent verifies that an HTTP request whose
// Host header is <prefix>.<corrID>.<zone> is attributed to the correct session.
func TestNative_HTTP_SubdomainPrefix_SavesEvent(t *testing.T) {
	sink := &testSink{}
	n, _, httpPort := newTestNative(t, sink)
	ctx := context.Background()

	ep, err := n.NewSession(ctx, "sess-prefix-http", "charlie")
	require.NoError(t, err)

	prefixedHost := "injected-data." + ep.DNS
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/cb", httpPort), nil)
	require.NoError(t, err)
	req.Host = prefixedHost

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Eventually(t, func() bool { return sink.Len() == 1 }, time.Second, 10*time.Millisecond)
	ev := sink.Events()[0]
	assert.Equal(t, "http", ev.Protocol)
	assert.Equal(t, "sess-prefix-http", ev.SessionID)
	assert.Equal(t, "charlie", ev.TenantID)
	// Full host (with the exfiltration prefix) must be present in event data
	assert.Equal(t, strings.ToLower(prefixedHost), ev.Data["host"])
}

// TestNative_RestoreSession_SavesEvent verifies that a session re-registered via
// RestoreSession (i.e. loaded back from the store after a process restart) still
// attributes incoming DNS and HTTP callbacks to the correct session.
func TestNative_RestoreSession_SavesEvent(t *testing.T) {
	sink := &testSink{}
	n, dnsPort, httpPort := newTestNative(t, sink)

	// Construct a corrID as NewSession would (CorrIDBytes*2 hex chars).
	b := make([]byte, oast.CorrIDBytes)
	for i := range b {
		b[i] = byte(0xab) // deterministic, not random
	}
	corrID := fmt.Sprintf("%x", b) // "abababababababababab" — 20 hex chars

	// Restore the session directly (simulating post-restart hydration).
	n.RestoreSession(corrID, "sess-restored", "dave")

	// --- DNS callback ---
	dnsName := corrID + "." + testZone
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dnsName), dns.TypeA)
	resp, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)

	require.Eventually(t, func() bool { return sink.Len() == 1 }, time.Second, 10*time.Millisecond)
	ev := sink.Events()[0]
	assert.Equal(t, "dns", ev.Protocol)
	assert.Equal(t, "sess-restored", ev.SessionID)
	assert.Equal(t, "dave", ev.TenantID)
	assert.Equal(t, strings.ToLower(dnsName), ev.Data["qname"])

	// --- HTTP callback ---
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/cb", httpPort), nil)
	require.NoError(t, err)
	req.Host = dnsName

	hresp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = hresp.Body.Close()
	assert.Equal(t, http.StatusOK, hresp.StatusCode)

	require.Eventually(t, func() bool { return sink.Len() == 2 }, time.Second, 10*time.Millisecond)
	ev2 := sink.Events()[1]
	assert.Equal(t, "http", ev2.Protocol)
	assert.Equal(t, "sess-restored", ev2.SessionID)
	assert.Equal(t, "dave", ev2.TenantID)
}

// TestNative_HTTP_BodyTruncated verifies that bodies larger than 64 KB are
// capped and body_truncated is set to true.
func TestNative_HTTP_BodyTruncated(t *testing.T) {
	sink := &testSink{}
	n, _, httpPort := newTestNative(t, sink)
	ctx := context.Background()

	ep, err := n.NewSession(ctx, "sess-trunc", "alice")
	require.NoError(t, err)

	bigBody := strings.Repeat("x", 65*1024) // 65 KB — exceeds the 64 KB cap
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/", httpPort),
		strings.NewReader(bigBody),
	)
	require.NoError(t, err)
	req.Host = ep.DNS

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.Eventually(t, func() bool { return sink.Len() == 1 }, time.Second, 10*time.Millisecond)

	data := sink.Events()[0].Data
	bodyStr, ok := data["body"].(string)
	require.True(t, ok, "body should be a string")
	assert.Len(t, bodyStr, 64*1024, "body should be capped at exactly 64 KB")
	assert.Equal(t, true, data["body_truncated"])
}
