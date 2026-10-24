package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/PiDmitrius/certview/internal/ssrfguard"
	"github.com/PiDmitrius/certview/internal/store"
)

func trustRoot(t *testing.T, h *handler, root *testCA) {
	t.Helper()
	info, err := h.ctx.ParseCertInfo(root.cert.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ImportTrustedCert(info.Subject, info.Issuer, info.Serial, info.SKI, info.AKI,
		info.SubjectNameDER, info.DER, true, true, "test"); err != nil {
		t.Fatal(err)
	}
}

func TestCRLOfACertificateThatMayNotSignCRLsIsIgnored(t *testing.T) {
	root := testIssue(t, "Signer Root", nil, true, nil)
	signer := testIssue(t, "Not a CA", root, false, func(c *x509.Certificate) { c.KeyUsage, c.SubjectKeyId = 0, []byte{1, 2, 3, 4} })
	url := "http://crl.test/signer.crl"
	child := testIssue(t, "Child of a leaf", signer, false, func(c *x509.Certificate) { c.CRLDistributionPoints = []string{url} })
	asIssuer := *signer.cert
	asIssuer.KeyUsage = x509.KeyUsageCRLSign
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour),
	}, &asIssuer, signer.key)
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler(t, fakeNet{url: func(*http.Request) []byte { return der }})
	trustRoot(t, h, root)
	resp := analyzeWith(t, h, child.cert.Raw, signer.cert.Raw, root.cert.Raw)
	if r := resp.Chain[0].Revocation; r != nil {
		t.Fatalf("revocation %q from a CRL signed by a non-CA", r.Status)
	}
	if stored, _ := h.store.FindFreshCRLByIssuer(resp.Chain[1].Subject); stored != nil {
		t.Fatal("CRL signed by a non-CA was stored")
	}
}

func TestOCSPStoredOnlyForTrustedIssuer(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		root := testIssue(t, "OCSP Store Root", nil, true, nil)
		url := fmt.Sprintf("http://ocsp.test/store-%v", trusted)
		leaf := testIssue(t, "Leaf", root, false, func(c *x509.Certificate) { c.OCSPServer = []string{url} })
		h := newTestHandler(t, fakeNet{url: ocspResponder(t, root, ocsp.Response{Status: ocsp.Good,
			SerialNumber: leaf.cert.SerialNumber, ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour)})})
		if trusted {
			trustRoot(t, h, root)
		}
		analyzeWith(t, h, leaf.cert.Raw, root.cert.Raw)
		stored, err := h.store.FindFreshOCSP(sha1Hex(leaf.cert.Raw))
		if err != nil {
			t.Fatal(err)
		}
		if (stored != nil) != trusted {
			t.Fatalf("trusted issuer %v: response stored %v", trusted, stored != nil)
		}
	}
}

func TestPublicErrorHidesDetails(t *testing.T) {
	for err, want := range map[error]string{
		fmt.Errorf("db.corp → 10.0.0.5: %w", ssrfguard.ErrBlocked):  "address is not public",
		&net.DNSError{Err: "no such host", Name: "db.corp"}:         "name not resolved",
		context.DeadlineExceeded:                                    "timeout",
		errors.New(`malformed HTTP response "SSH-2.0-OpenSSH_9.6"`): "connection failed or invalid response",
		&statusError{404}: "HTTP 404",
		&recentFailure{time.Minute, &statusError{500}}: "failed within the last 1m0s: HTTP 500",
	} {
		if got := publicError(err); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
}

func TestAdminListenerServesLocalhostOnly(t *testing.T) {
	h := localOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for host, want := range map[string]int{
		"localhost:8081":    http.StatusOK,
		"[::1]:8081":        http.StatusOK,
		"127.0.0.1":         http.StatusOK,
		"evil.example:8081": http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/analyze", strings.NewReader("-----BEGIN CERTIFICATE-----"))
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: HTTP %d, want %d", host, rec.Code, want)
		}
	}
}

func TestTrustTakesOnlyJSON(t *testing.T) {
	h := newTestHandler(t, fakeNet{})
	req := httptest.NewRequest(http.MethodPost, "/api/trust", strings.NewReader(`{"sha256":"AA"}`))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.trust(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain trust: HTTP %d", rec.Code)
	}
}

func TestCRLDownloadStopsAtNonObject(t *testing.T) {
	for body, ok := range map[string]bool{
		"-----BEGIN X509 CRL-----":            true,
		"\x30\x82\x01\x00":                    true,
		"\x30\x84\x7f\xff\xff\xff":            false,
		"SSH-2.0-OpenSSH_9.6\r\n":             false,
		"<html><body>Not found</body></html>": false,
	} {
		err := checkObjectStart(bufio.NewReader(strings.NewReader(body)), maxCRLSize)
		if (err == nil) != ok {
			t.Errorf("%q: %v", body, err)
		}
	}
}

func TestOversizedInputRejectedBeforeParsing(t *testing.T) {
	h := newTestHandler(t, fakeNet{})
	resp := analyzeWith(t, h, bytes.Repeat([]byte{'A'}, 3*64<<10))
	if !strings.HasPrefix(resp.Verify.Message, "Input too large") {
		t.Fatalf("verify %q", resp.Verify.Message)
	}
}

func TestOnlyChainCertificatesFromAIAAreArchived(t *testing.T) {
	root := testIssue(t, "AIA Root", nil, true, nil)
	inter := testIssue(t, "AIA CA", root, true, nil)
	url := "http://aia.test/bundle.pem"
	leaf := testIssue(t, "AIA Leaf", inter, false, func(c *x509.Certificate) { c.IssuingCertificateURL = []string{url} })
	extra := []*testCA{testIssue(t, "Unrelated 1", nil, true, nil), testIssue(t, "Unrelated 2", nil, true, nil)}
	var bundle bytes.Buffer
	for _, c := range append([]*testCA{inter}, extra...) {
		pem.Encode(&bundle, &pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
	}
	h := newTestHandler(t, fakeNet{url: func(*http.Request) []byte { return bundle.Bytes() }})
	resp := analyzeWith(t, h, leaf.cert.Raw, root.cert.Raw)
	if len(resp.Chain) != 3 {
		t.Fatalf("chain of %d", len(resp.Chain))
	}
	if !h.store.HasDER(store.SHA256Hex(inter.cert.Raw)) {
		t.Fatal("chain CA from AIA not archived")
	}
	for _, c := range extra {
		if h.store.HasDER(store.SHA256Hex(c.cert.Raw)) {
			t.Fatalf("%s from AIA archived", c.cert.Subject.CommonName)
		}
	}
}
