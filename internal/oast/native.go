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

package oast

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/miekg/dns"
	"github.com/dguerri/oast-mcp/internal/store"
)

// Native is an in-process OAST responder. It runs a DNS server (UDP) on dnsPort
// and an HTTP callback server on httpPort. Events are saved synchronously to sink
// when DNS queries or HTTP requests arrive — no polling required.
type Native struct {
	zone            string
	publicIP        string
	ip4             net.IP
	dnsBindAddr     string // empty = all interfaces
	httpBindAddr    string
	dnsPort         int
	httpPort        int
	tsigKeyName     string            // e.g. "caddy." — empty = RFC 2136 disabled
	tsigKeyB64      string            // base64-encoded secret for miekg/dns TsigSecret map
	tsigAllowedAddr string            // source IP allowed to send RFC 2136 UPDATEs; empty = any
	txtRecords      map[string]string // protected by n.mu; name (FQDN, no dot) → TXT value
	sink            EventSink
	logger          *slog.Logger

	mu       sync.RWMutex
	sessions map[string]sessionMeta

	cancelMu sync.Mutex
	cancel   context.CancelFunc

	dnsUDPServer *dns.Server
	dnsTCPServer *dns.Server
	httpServer   *http.Server
}

// CorrIDBytes is the number of random bytes used to generate a correlation ID.
// The hex-encoded string representation is CorrIDBytes*2 characters long.
const CorrIDBytes = 10

// normaliseTSIGKeyName ensures the key name has a trailing dot (required by miekg/dns).
// Returns empty string unchanged so the disabled state is unambiguously "".
func normaliseTSIGKeyName(name string) string {
	if name == "" {
		return ""
	}
	return strings.TrimSuffix(name, ".") + "."
}

// NewNative constructs a Native responder. Call StartPolling to start the servers.
func NewNative(zone, publicIP, dnsBindAddr, httpBindAddr string,
	dnsPort, httpPort int,
	tsigKeyName, tsigKeyHex, tsigAllowedAddr string,
	sink EventSink, logger *slog.Logger) *Native {
	var tsigKeyB64 string
	if tsigKeyHex != "" {
		b, err := hex.DecodeString(tsigKeyHex)
		if err != nil {
			logger.Warn("invalid tsig_key_hex, RFC 2136 disabled", "err", err)
		} else {
			tsigKeyB64 = base64.StdEncoding.EncodeToString(b)
		}
	}
	return &Native{
		zone:            strings.TrimSuffix(strings.ToLower(zone), "."),
		publicIP:        publicIP,
		dnsBindAddr:     dnsBindAddr,
		httpBindAddr:    httpBindAddr,
		dnsPort:         dnsPort,
		httpPort:        httpPort,
		tsigKeyName:     normaliseTSIGKeyName(tsigKeyName),
		tsigKeyB64:      tsigKeyB64,
		tsigAllowedAddr: tsigAllowedAddr,
		txtRecords:      make(map[string]string),
		sink:            sink,
		logger:          logger,
		sessions:        make(map[string]sessionMeta),
	}
}

// RestoreSession re-registers a corrID→session mapping that was previously
// persisted to the store but lost when the process restarted. It must be
// called during startup (before StartPolling) for every active session read
// back from the database, so that incoming DNS/HTTP callbacks are still
// attributed to the correct session.
func (n *Native) RestoreSession(corrID, sessionID, tenantID string) {
	n.mu.Lock()
	n.sessions[corrID] = sessionMeta{sessionID: sessionID, tenantID: tenantID}
	n.mu.Unlock()
}

// NewSession generates a random correlation ID, registers it, and returns callback endpoints.
func (n *Native) NewSession(_ context.Context, sessionID, tenantID string) (*Endpoints, error) {
	b := make([]byte, CorrIDBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate correlation id: %w", err)
	}
	corrID := hex.EncodeToString(b)

	n.mu.Lock()
	n.sessions[corrID] = sessionMeta{sessionID: sessionID, tenantID: tenantID}
	n.mu.Unlock()

	return &Endpoints{
		CorrelationID: corrID,
		DNS:           fmt.Sprintf("%s.%s", corrID, n.zone),
		HTTP:          fmt.Sprintf("http://%s.%s", corrID, n.zone),
		HTTPS:         fmt.Sprintf("https://%s.%s", corrID, n.zone),
	}, nil
}

// StartPolling starts the DNS and HTTP servers. "Polling" is a misnomer here
// (kept for interface compatibility) — events arrive in-band, no polling needed.
func (n *Native) StartPolling(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	n.cancelMu.Lock()
	n.cancel = cancel
	n.cancelMu.Unlock()

	if err := n.startDNS(ctx); err != nil {
		cancel()
		return fmt.Errorf("start dns server: %w", err)
	}
	if err := n.startHTTP(ctx); err != nil {
		cancel()
		_ = n.dnsUDPServer.Shutdown()
		_ = n.dnsTCPServer.Shutdown()
		return fmt.Errorf("start http server: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the DNS and HTTP servers.
func (n *Native) Stop() {
	n.cancelMu.Lock()
	fn := n.cancel
	n.cancelMu.Unlock()
	if fn != nil {
		fn()
	}
	if n.dnsUDPServer != nil {
		_ = n.dnsUDPServer.Shutdown()
	}
	if n.dnsTCPServer != nil {
		_ = n.dnsTCPServer.Shutdown()
	}
	if n.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = n.httpServer.Shutdown(ctx)
	}
}

func (n *Native) startDNS(ctx context.Context) error {
	ip := net.ParseIP(n.publicIP)
	if ip == nil {
		return fmt.Errorf("invalid public_ip %q: not a valid IP address", n.publicIP)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("invalid public_ip %q: not an IPv4 address", n.publicIP)
	}
	n.ip4 = ip4

	mux := dns.NewServeMux()
	mux.HandleFunc(n.zone+".", func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Opcode == dns.OpcodeUpdate {
			n.handleUpdate(w, r)
		} else {
			n.handleDNS(w, r)
		}
	})

	// Accept UPDATE messages (OpcodeUpdate=5) in addition to the default
	// OpcodeQuery and OpcodeNotify. The DefaultMsgAcceptFunc rejects them.
	acceptFunc := func(dh dns.Header) dns.MsgAcceptAction {
		opcode := int(dh.Bits>>11) & 0xF
		if opcode == dns.OpcodeUpdate {
			return dns.MsgAccept
		}
		return dns.DefaultMsgAcceptFunc(dh)
	}
	tsigSecrets := map[string]string{}
	if n.tsigKeyName != "" && n.tsigKeyB64 != "" {
		tsigSecrets[n.tsigKeyName] = n.tsigKeyB64
	}

	udpStarted := make(chan struct{})
	n.dnsUDPServer = &dns.Server{
		Addr:              fmt.Sprintf("%s:%d", n.dnsBindAddr, n.dnsPort),
		Net:               "udp",
		Handler:           mux,
		NotifyStartedFunc: func() { close(udpStarted) },
		MsgAcceptFunc:     acceptFunc,
		TsigSecret:        tsigSecrets,
	}
	go func() {
		if err := n.dnsUDPServer.ListenAndServe(); err != nil && ctx.Err() == nil {
			n.logger.Error("dns udp server stopped", "err", err)
		}
	}()

	tcpStarted := make(chan struct{})
	n.dnsTCPServer = &dns.Server{
		Addr:              fmt.Sprintf("%s:%d", n.dnsBindAddr, n.dnsPort),
		Net:               "tcp",
		Handler:           mux,
		NotifyStartedFunc: func() { close(tcpStarted) },
		MsgAcceptFunc:     acceptFunc,
		TsigSecret:        tsigSecrets,
	}
	go func() {
		if err := n.dnsTCPServer.ListenAndServe(); err != nil && ctx.Err() == nil {
			n.logger.Error("dns tcp server stopped", "err", err)
		}
	}()

	timeout := time.After(2 * time.Second)
	select {
	case <-udpStarted:
	case <-timeout:
		return fmt.Errorf("dns udp server did not start within 2s")
	}
	select {
	case <-tcpStarted:
	case <-timeout:
		return fmt.Errorf("dns tcp server did not start within 2s")
	}
	return nil
}

func (n *Native) startHTTP(ctx context.Context) error {
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", n.httpBindAddr, n.httpPort))
	if err != nil {
		return fmt.Errorf("bind http callback port %d: %w", n.httpPort, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", n.handleHTTP)
	n.httpServer = &http.Server{Handler: mux}
	go func() {
		if err := n.httpServer.Serve(l); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
			n.logger.Error("http callback server stopped", "err", err)
		}
	}()
	return nil
}

// soaRR returns the SOA record for the zone.
func (n *Native) soaRR() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(n.zone),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Ns:      "ns1." + dns.Fqdn(n.zone),
		Mbox:    "hostmaster." + dns.Fqdn(n.zone),
		Serial:  1,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  60,
	}
}

// SetTXT stores a TXT record value for name. Used for ACME DNS-01 challenges.
func (n *Native) SetTXT(name, value string) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	n.mu.Lock()
	n.txtRecords[name] = value
	n.mu.Unlock()
}

// DeleteTXT removes a TXT record for name.
func (n *Native) DeleteTXT(name string) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	n.mu.Lock()
	delete(n.txtRecords, name)
	n.mu.Unlock()
}

// handleDNS answers A and SOA queries for *.zone and saves an event for A queries.
func (n *Native) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: n.ip4,
			}
			m.Answer = append(m.Answer, rr)

			qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))
			corrID := n.extractCorrID(qname)
			if corrID != "" {
				n.saveEvent(context.Background(), corrID, "dns",
					w.RemoteAddr().String(),
					map[string]any{"qname": qname, "qtype": "A"},
				)
			}
		case dns.TypeNS:
			qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))
			if qname == n.zone {
				m.Answer = append(m.Answer, &dns.NS{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Ns: "ns1." + dns.Fqdn(n.zone),
				})
			}
		case dns.TypeSOA:
			qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))
			if qname == n.zone {
				// Zone apex: SOA goes in Answer section
				m.Answer = append(m.Answer, n.soaRR())
			} else {
				// Subdomain with no record: SOA goes in Authority section
				m.Ns = append(m.Ns, n.soaRR())
			}
		case dns.TypeTXT:
			qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))
			n.mu.RLock()
			val, ok := n.txtRecords[qname]
			n.mu.RUnlock()
			if ok {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Txt: []string{val},
				})
			}
		}
	}

	if err := w.WriteMsg(m); err != nil {
		n.logger.Warn("dns write response", "err", err)
	}
}

const maxBodySize = 64 * 1024 // 64 KB

// hopByHopHeaders are RFC 2616 §13.5.1 hop-by-hop headers that should not be
// stored in events. Content-Length is also excluded (derivable from body length).
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Content-Length":      true,
}

// handleHTTP records an HTTP callback event for the matching session.
func (n *Native) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := canonicalHost(r.Host)
	corrID := n.extractCorrID(host)
	if corrID == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	srcIP, data := buildHTTPData(r, host)
	n.saveEvent(r.Context(), corrID, "http", srcIP, data)
	w.WriteHeader(http.StatusOK)
}

// canonicalHost strips the port from a Host header and lowercases the result.
func canonicalHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

// buildHTTPData constructs the event data map and resolves the real source IP.
// Caddy appends the real connecting IP to X-Forwarded-For, so the last entry
// is trustworthy; earlier entries are client-supplied and logged for context.
func buildHTTPData(r *http.Request, host string) (srcIP string, data map[string]any) {
	srcIP = r.RemoteAddr
	data = map[string]any{
		"method": r.Method,
		"path":   r.URL.Path,
		"host":   host,
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		srcIP = strings.TrimSpace(parts[len(parts)-1])
		data["x_forwarded_for"] = xff
	}
	if qs := r.URL.RawQuery; qs != "" {
		data["query_string"] = qs
	}
	if ua := r.Header.Get("User-Agent"); ua != "" {
		data["user_agent"] = ua
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		data["content_type"] = ct
	}
	if hdrs := collectHTTPHeaders(r); len(hdrs) > 0 {
		data["headers"] = hdrs
	}
	addHTTPBody(r, data)
	return
}

// collectHTTPHeaders returns all non-hop-by-hop request headers as a map.
func collectHTTPHeaders(r *http.Request) map[string]any {
	hdrs := make(map[string]any)
	for name, vals := range r.Header {
		if hopByHopHeaders[name] {
			continue
		}
		if len(vals) == 1 {
			hdrs[name] = vals[0]
		} else {
			anyVals := make([]any, len(vals))
			for i, v := range vals {
				anyVals[i] = v
			}
			hdrs[name] = anyVals
		}
	}
	return hdrs
}

// addHTTPBody reads the request body (up to maxBodySize) and adds it to data.
func addHTTPBody(r *http.Request, data map[string]any) {
	if r.Body == nil {
		return
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil || len(buf) == 0 {
		return
	}
	truncated := len(buf) > maxBodySize
	if truncated {
		buf = buf[:maxBodySize]
	}
	if utf8.Valid(buf) {
		data["body"] = string(buf)
	} else {
		data["body"] = base64.StdEncoding.EncodeToString(buf)
		data["body_encoding"] = "base64"
	}
	data["body_truncated"] = truncated
}

// extractCorrID returns the correlation ID for names under n.zone,
// or empty string if the name is not under n.zone.
//
// The corrID is always the label immediately to the left of the zone suffix.
// Four hostname shapes are supported:
//
//   - Plain:        <corrID>.<zone>
//   - Labelled:     <corrID>-<label>.<zone>          (wildcard-TLS safe, single extra label)
//   - DNS-prefixed: <prefix>.<corrID>.<zone>          (DNS only — multi-label escapes wildcard TLS)
//   - Combined:     <prefix>.<corrID>-<label>.<zone>  (DNS only)
//
// Because the corrID is always exactly CorrIDBytes*2 hex characters, we take
// the first CorrIDBytes*2 characters of the rightmost label, stripping any
// trailing "-label" suffix.
func (n *Native) extractCorrID(name string) string {
	if name == n.zone {
		return ""
	}
	suffix := "." + n.zone
	if !strings.HasSuffix(name, suffix) {
		return ""
	}
	sub := strings.TrimSuffix(name, suffix)
	labels := strings.Split(sub, ".")
	rightmost := labels[len(labels)-1]
	// The corrID occupies the first CorrIDBytes*2 characters; an optional
	// "-label" suffix may follow. Truncate to strip it.
	corrIDStrLen := CorrIDBytes * 2
	if len(rightmost) >= corrIDStrLen {
		return rightmost[:corrIDStrLen]
	}
	return rightmost
}

// handleUpdate processes RFC 2136 DNS UPDATE messages.
// Only accepts messages signed with the configured TSIG key.
// If tsigAllowedAddr is set, only that source IP is accepted.
// Only TXT records under _acme-challenge.<zone> may be modified.
func (n *Native) handleUpdate(w dns.ResponseWriter, r *dns.Msg) {
	reply := func(rcode int) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		if r.IsTsig() != nil && rcode == dns.RcodeSuccess {
			w.TsigTimersOnly(true)
		}
		_ = w.WriteMsg(m)
	}

	if rcode := n.checkUpdateAuth(w, r); rcode != dns.RcodeSuccess {
		reply(rcode)
		return
	}

	// Process update records (r.Ns holds the update section).
	for _, rr := range r.Ns {
		hdr := rr.Header()
		name := strings.ToLower(strings.TrimSuffix(hdr.Name, "."))
		if hdr.Rrtype != dns.TypeTXT || !strings.HasPrefix(name, "_acme-challenge.") {
			n.logger.Warn("RFC 2136 UPDATE for disallowed target refused", "name", name, "type", hdr.Rrtype)
			reply(dns.RcodeRefused)
			return
		}
		n.applyTXTUpdate(name, hdr, rr)
	}

	reply(dns.RcodeSuccess)
}

// checkUpdateAuth enforces source IP and TSIG authentication for RFC 2136 UPDATEs.
// Returns a DNS rcode — RcodeSuccess means the request is authorised.
func (n *Native) checkUpdateAuth(w dns.ResponseWriter, r *dns.Msg) int {
	if n.tsigAllowedAddr != "" {
		host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		if host != n.tsigAllowedAddr {
			n.logger.Warn("RFC 2136 UPDATE from disallowed address refused",
				"addr", w.RemoteAddr(), "allowed", n.tsigAllowedAddr)
			return dns.RcodeRefused
		}
	}
	if n.tsigKeyName == "" {
		return dns.RcodeSuccess
	}
	tsig := r.IsTsig()
	if tsig == nil {
		n.logger.Warn("RFC 2136 UPDATE without TSIG refused")
		return dns.RcodeRefused
	}
	// Also verify the key name matches our configured key.
	if tsig.Hdr.Name != n.tsigKeyName {
		n.logger.Warn("RFC 2136 UPDATE with unknown TSIG key refused", "key", tsig.Hdr.Name)
		return dns.RcodeRefused
	}
	// miekg/dns stores the TSIG verification result in w.TsigStatus() rather than
	// rejecting automatically. Check that the HMAC is valid.
	if err := w.TsigStatus(); err != nil {
		n.logger.Warn("RFC 2136 UPDATE TSIG verification failed", "err", err)
		return dns.RcodeNotAuth
	}
	return dns.RcodeSuccess
}

// applyTXTUpdate adds or removes a TXT record based on the RR class.
func (n *Native) applyTXTUpdate(name string, hdr *dns.RR_Header, rr dns.RR) {
	switch hdr.Class {
	case dns.ClassINET: // ADD
		if txt, ok := rr.(*dns.TXT); ok && len(txt.Txt) > 0 {
			n.mu.Lock()
			n.txtRecords[name] = txt.Txt[0]
			n.mu.Unlock()
			n.logger.Info("RFC 2136 TXT added", "name", name, "value", txt.Txt[0])
		}
	case dns.ClassNONE: // DELETE specific value (RFC 2136 §2.5.4)
		txt, ok := rr.(*dns.TXT)
		if !ok || len(txt.Txt) == 0 {
			return
		}
		requested := txt.Txt[0]
		n.mu.Lock()
		stored, exists := n.txtRecords[name]
		if exists && stored == requested {
			delete(n.txtRecords, name)
			n.mu.Unlock()
			n.logger.Info("RFC 2136 TXT deleted", "name", name, "value", requested)
		} else {
			n.mu.Unlock()
			n.logger.Warn("RFC 2136 TXT delete skipped: value mismatch",
				"name", name, "requested", requested, "stored", stored, "exists", exists)
		}
	case dns.ClassANY: // DELETE entire RRset regardless of value (RFC 2136 §2.5.2)
		n.mu.Lock()
		stored, exists := n.txtRecords[name]
		delete(n.txtRecords, name)
		n.mu.Unlock()
		if exists {
			n.logger.Info("RFC 2136 TXT RRset deleted", "name", name, "value", stored)
		}
	}
}

// saveEvent looks up the session for corrID and persists the interaction.
func (n *Native) saveEvent(ctx context.Context, corrID, protocol, srcIP string, data map[string]any) {
	n.mu.RLock()
	meta, ok := n.sessions[corrID]
	n.mu.RUnlock()
	if !ok {
		n.logger.Debug("no session for corrID", "corrID", corrID, "protocol", protocol)
		return
	}

	now := time.Now().UTC()
	ev := &store.Event{
		EventID:    fmt.Sprintf("%s_%s_%d", corrID, protocol, now.UnixNano()),
		SessionID:  meta.sessionID,
		TenantID:   meta.tenantID,
		ReceivedAt: now,
		Protocol:   protocol,
		SrcIP:      srcIP,
		Data:       data,
	}
	if err := n.sink.SaveEvent(ctx, ev); err != nil {
		n.logger.Error("save event", "err", err)
	}
}
