// SPDX-License-Identifier: GPL-3.0-or-later
//
// astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Command miekgclient is the T-TEST-09 cert-manager interop contract client.
//
// It drives a REAL github.com/miekg/dns client — the exact library cert-manager's
// rfc2136 DNS-01 solver is built on — against a running astropath RFC2136 listener
// and reports machine-readable (JSON) verdicts to stdout. A dnspython-vs-dnspython
// round-trip lenient-agrees and hides the one interop-critical, source-level fact
// this client exists to prove: cert-manager's client VERIFIES THE TSIG ON THE
// REPLY. miekg's Conn.ReadMsg (client.go) only runs that verification when the
// reply itself carries a TSIG, so the load-bearing assertion for every signed
// exchange is BOTH:
//
//	reply_had_tsig == true   (the reply is signed at all — catches an unsigned
//	                          reply, which cert-manager rejects → order never
//	                          advances → the certificate never issues), AND
//	err == nil               (miekg's own independent HMAC recomputation accepts
//	                          astropath's MAC bytes — catches a badly-signed reply
//	                          that a dnspython-only test would lenient-agree with).
//
// The cert-manager-shaped sequence, over both UDP and TCP:
//
//	signed UPDATE add    _acme-challenge.<zone>. TXT "<token>"  -> NOERROR, signed
//	signed UPDATE delete same RRset, class NONE (cleanup shape) -> NOERROR, signed
//
// Negative controls (astropath policy, SPEC §3):
//
//	unsigned UPDATE            -> NOTAUTH  (reply to an unsigned request is itself
//	                                        unsigned by design — assert rcode only)
//	signed SOA QUERY           -> REFUSED  (deliberate no-SOA-answering in M1; the
//	                                        REFUSED reply is itself TSIG-signed)
//	UPDATE with a WRONG secret -> NOTAUTH  (server signs a BADSIG error reply with
//	                                        the correct key; this client, holding
//	                                        the wrong key, cannot verify it — the
//	                                        verify error is EXPECTED, the verdict
//	                                        is rcode==NOTAUTH + BADSIG error field)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/miekg/dns"
)

// scenarioResult is one machine-readable verdict line.
type scenarioResult struct {
	Name           string `json:"name"`
	Transport      string `json:"transport"`
	Op             string `json:"op"`
	SignedRequest  bool   `json:"signed_request"`
	ExpectedRcode  string `json:"expected_rcode"`
	Rcode          string `json:"rcode"`
	ReplyHadTSIG   bool   `json:"reply_had_tsig"`
	ReplyTSIGValid bool   `json:"reply_tsig_valid"`
	TSIGErrorField string `json:"tsig_error_field"`
	ExchangeError  string `json:"exchange_error"`
	Pass           bool   `json:"pass"`
	Detail         string `json:"detail"`
}

// report is the full JSON document emitted to stdout.
type report struct {
	Server       string           `json:"server"`
	MiekgVersion string           `json:"miekg_version"`
	KeyName      string           `json:"key_name"`
	Algorithm    string           `json:"algorithm"`
	Zone         string           `json:"zone"`
	FQDN         string           `json:"fqdn"`
	Token        string           `json:"token"`
	Scenarios    []scenarioResult `json:"scenarios"`
	AllPass      bool             `json:"all_pass"`
}

// config holds the resolved CLI flags for one run.
type config struct {
	server      string
	keyName     string
	secret      string
	wrongSecret string
	algorithm   string
	zone        string
	fqdn        string
	token       string
	timeout     time.Duration
}

func rcodeString(r *dns.Msg) string {
	if r == nil {
		return ""
	}
	if s, ok := dns.RcodeToString[r.Rcode]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", r.Rcode)
}

func replyHadTSIG(r *dns.Msg) bool {
	return r != nil && r.IsTsig() != nil
}

// tsigErrorField reads the TSIG RR Error field from a reply (16/17/18 -> name).
func tsigErrorField(r *dns.Msg) string {
	if r == nil {
		return ""
	}
	t := r.IsTsig()
	if t == nil {
		return ""
	}
	switch t.Error {
	case dns.RcodeSuccess:
		return "NOERROR"
	case dns.RcodeBadSig:
		return "BADSIG"
	case dns.RcodeBadKey:
		return "BADKEY"
	case dns.RcodeBadTime:
		return "BADTIME"
	default:
		return fmt.Sprintf("TSIGERR%d", t.Error)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func txtRR(fqdn, token string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Txt: []string{token},
	}
}

func newClient(net string, secret map[string]string, timeout time.Duration) *dns.Client {
	c := new(dns.Client)
	c.Net = net
	c.Timeout = timeout
	if secret != nil {
		c.TsigSecret = secret
	}
	return c
}

// runSignedUpdate performs a TSIG-signed UPDATE (add or delete) over transport
// and asserts NOERROR plus a reply TSIG that verifies under miekg's own HMAC.
func runSignedUpdate(cfg config, transport, op string) scenarioResult {
	m := new(dns.Msg)
	m.SetUpdate(cfg.zone)
	rr := txtRR(cfg.fqdn, cfg.token)
	switch op {
	case "add":
		m.Insert([]dns.RR{rr}) // class IN
	case "delete":
		m.Remove([]dns.RR{rr}) // class NONE — cert-manager cleanup shape
	}
	m.SetTsig(cfg.keyName, cfg.algorithm, 300, time.Now().Unix())

	c := newClient(transport, map[string]string{cfg.keyName: cfg.secret}, cfg.timeout)
	r, _, err := c.Exchange(m, cfg.server)

	res := scenarioResult{
		Name:           transport + "_" + op,
		Transport:      transport,
		Op:             op,
		SignedRequest:  true,
		ExpectedRcode:  "NOERROR",
		Rcode:          rcodeString(r),
		ReplyHadTSIG:   replyHadTSIG(r),
		ReplyTSIGValid: err == nil && replyHadTSIG(r),
		TSIGErrorField: tsigErrorField(r),
		ExchangeError:  errString(err),
	}
	res.Pass = err == nil && r != nil && r.Rcode == dns.RcodeSuccess && res.ReplyHadTSIG
	if res.Pass {
		res.Detail = "signed reply carried a TSIG that verified under miekg/dns"
	} else {
		res.Detail = "expected NOERROR with a miekg-verified signed reply"
	}
	return res
}

// runUnsignedUpdate sends an UNSIGNED UPDATE. astropath's auth gate rejects it
// NOTAUTH and answers with an unsigned reply; miekg is not asked to verify.
func runUnsignedUpdate(cfg config) scenarioResult {
	m := new(dns.Msg)
	m.SetUpdate(cfg.zone)
	m.Insert([]dns.RR{txtRR(cfg.fqdn, cfg.token)})

	c := newClient("udp", nil, cfg.timeout)
	r, _, err := c.Exchange(m, cfg.server)

	res := scenarioResult{
		Name:           "unsigned_update",
		Transport:      "udp",
		Op:             "add",
		SignedRequest:  false,
		ExpectedRcode:  "NOTAUTH",
		Rcode:          rcodeString(r),
		ReplyHadTSIG:   replyHadTSIG(r),
		TSIGErrorField: tsigErrorField(r),
		ExchangeError:  errString(err),
	}
	res.Pass = err == nil && r != nil && r.Rcode == dns.RcodeNotAuth
	res.Detail = "unsigned UPDATE rejected NOTAUTH by the auth gate; reply unsigned"
	return res
}

// runSignedSOAQuery sends a TSIG-signed SOA QUERY. M1 answers no SOA: the query
// is REFUSED, and (being signed) the REFUSED reply is itself TSIG-signed.
func runSignedSOAQuery(cfg config) scenarioResult {
	m := new(dns.Msg)
	m.SetQuestion(cfg.zone, dns.TypeSOA)
	m.SetTsig(cfg.keyName, cfg.algorithm, 300, time.Now().Unix())

	c := newClient("udp", map[string]string{cfg.keyName: cfg.secret}, cfg.timeout)
	r, _, err := c.Exchange(m, cfg.server)

	res := scenarioResult{
		Name:           "soa_query_signed",
		Transport:      "udp",
		Op:             "query",
		SignedRequest:  true,
		ExpectedRcode:  "REFUSED",
		Rcode:          rcodeString(r),
		ReplyHadTSIG:   replyHadTSIG(r),
		ReplyTSIGValid: err == nil && replyHadTSIG(r),
		TSIGErrorField: tsigErrorField(r),
		ExchangeError:  errString(err),
	}
	res.Pass = err == nil && r != nil && r.Rcode == dns.RcodeRefused && res.ReplyHadTSIG
	res.Detail = "no-SOA-answering: signed SOA QUERY REFUSED with a verified signed reply"
	return res
}

// runWrongKeyUpdate signs with the SAME key name but the WRONG secret. The
// server replies with a BADSIG error signed by the correct key; this client
// holds the wrong key, so a reply verify error is EXPECTED (not a failure). The
// verdict is rcode==NOTAUTH, with the reply TSIG error field in the BADSIG family.
func runWrongKeyUpdate(cfg config) scenarioResult {
	m := new(dns.Msg)
	m.SetUpdate(cfg.zone)
	m.Insert([]dns.RR{txtRR(cfg.fqdn, cfg.token)})
	m.SetTsig(cfg.keyName, cfg.algorithm, 300, time.Now().Unix())

	c := newClient("udp", map[string]string{cfg.keyName: cfg.wrongSecret}, cfg.timeout)
	r, _, err := c.Exchange(m, cfg.server)

	res := scenarioResult{
		Name:           "wrong_key_update",
		Transport:      "udp",
		Op:             "add",
		SignedRequest:  true,
		ExpectedRcode:  "NOTAUTH",
		Rcode:          rcodeString(r),
		ReplyHadTSIG:   replyHadTSIG(r),
		TSIGErrorField: tsigErrorField(r),
		ExchangeError:  errString(err),
	}
	res.Pass = r != nil && r.Rcode == dns.RcodeNotAuth
	res.Detail = "wrong-secret UPDATE rejected NOTAUTH; reply verify error is expected"
	return res
}

func miekgVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/miekg/dns" {
			return dep.Version
		}
	}
	return "unknown"
}

func run(cfg config) report {
	rep := report{
		Server:       cfg.server,
		MiekgVersion: miekgVersion(),
		KeyName:      cfg.keyName,
		Algorithm:    cfg.algorithm,
		Zone:         cfg.zone,
		FQDN:         cfg.fqdn,
		Token:        cfg.token,
		Scenarios: []scenarioResult{
			runSignedUpdate(cfg, "udp", "add"),
			runSignedUpdate(cfg, "udp", "delete"),
			runSignedUpdate(cfg, "tcp", "add"),
			runSignedUpdate(cfg, "tcp", "delete"),
			runUnsignedUpdate(cfg),
			runSignedSOAQuery(cfg),
			runWrongKeyUpdate(cfg),
		},
	}
	rep.AllPass = true
	for _, s := range rep.Scenarios {
		if !s.Pass {
			rep.AllPass = false
		}
	}
	return rep
}

func main() {
	var cfg config
	flag.StringVar(&cfg.server, "server", "", "astropath RFC2136 listener host:port (required)")
	flag.StringVar(&cfg.keyName, "keyname", "cm-key.", "TSIG key name (fqdn, trailing dot)")
	flag.StringVar(&cfg.secret, "secret", "", "correct TSIG secret, base64 (required)")
	flag.StringVar(&cfg.wrongSecret, "wrongsecret", "", "a different (wrong) TSIG secret, base64 (required)")
	flag.StringVar(&cfg.algorithm, "algorithm", dns.HmacSHA256, "TSIG algorithm in miekg naming (hmac-sha256.)")
	flag.StringVar(&cfg.zone, "zone", "example.com.", "managed zone (fqdn)")
	flag.StringVar(&cfg.fqdn, "fqdn", "_acme-challenge.example.com.", "challenge record owner (fqdn)")
	flag.StringVar(&cfg.token, "token", "Vv8kAx_1qz3nQ2rJ5tXbC9dwE7fLmN0pR4sU6yZ8aQk", "ACME DNS-01 TXT token value")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "per-exchange timeout")
	flag.Parse()

	if cfg.server == "" || cfg.secret == "" || cfg.wrongSecret == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: -server, -secret and -wrongsecret are required")
		os.Exit(2)
	}

	rep := run(cfg)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !rep.AllPass {
		os.Exit(1)
	}
}
