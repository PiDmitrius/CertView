package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PiDmitrius/certview/internal/store"
)

type noNet struct{ t *testing.T }

func (n noNet) RoundTrip(req *http.Request) (*http.Response, error) {
	n.t.Errorf("network request %s %s", req.Method, req.URL)
	return nil, errors.New("no network")
}

func postLink(t *testing.T, h *handler, certs ...string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string][]string{"certs": certs})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.analyzeLink(rec, httptest.NewRequest(http.MethodPost, "/api/link", strings.NewReader(string(body))))
	return rec
}

func b64url(der []byte) string { return base64.RawURLEncoding.EncodeToString(der) }

func TestLinkChainWithoutNetwork(t *testing.T) {
	h := newTestHandler(t, nil)
	h.client = &http.Client{Transport: noNet{t}}
	h.analysisCache = newRespCache[analyzeResponse](0)

	aia := func(c *x509.Certificate) { c.IssuingCertificateURL = []string{"http://aia.test/issuer.crt"} }
	root := testIssue(t, "Link Root", nil, true, nil)
	inter := testIssue(t, "Link CA", root, true, aia)
	leaf := testIssue(t, "Link Leaf", inter, false, aia)
	rootInfo, err := h.ctx.ParseCertInfo(root.cert.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ImportTrustedCert(rootInfo.Subject, rootInfo.Issuer, rootInfo.Serial, rootInfo.SKI, rootInfo.AKI,
		rootInfo.SubjectNameDER, rootInfo.DER, true, true, "test"); err != nil {
		t.Fatal(err)
	}

	rec := postLink(t, h, b64url(leaf.cert.Raw), b64url(inter.cert.Raw), b64url(root.cert.Raw))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body)
	}
	var resp analyzeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Chain) != 3 || resp.Verify.Status != "ok" || !resp.Verify.Trusted {
		t.Fatalf("chain of %d, %s, trusted %v: %s", len(resp.Chain), resp.Verify.Status, resp.Verify.Trusted, resp.Verify.Message)
	}
	for _, c := range []*testCA{leaf, inter} {
		if !h.store.HasDER(store.SHA256Hex(c.cert.Raw)) {
			t.Fatalf("%s from the link was not stored", c.cert.Subject.CommonName)
		}
	}

	// A leaf alone looks for its issuer as an upload does
	h.client = &http.Client{Transport: fakeNet{}}
	if rec := postLink(t, h, b64url(leaf.cert.Raw)); rec.Code != http.StatusOK {
		t.Fatalf("single-certificate link: HTTP %d: %s", rec.Code, rec.Body)
	}
}

func TestBadLink(t *testing.T) {
	h := newTestHandler(t, nil)
	h.client = &http.Client{Transport: noNet{t}}
	h.analysisCache = newRespCache[analyzeResponse](0)
	leaf := b64url(testIssue(t, "Leaf", nil, false, nil).cert.Raw)

	many := make([]string, maxChainDepth+1)
	for i := range many {
		many[i] = leaf
	}
	for name, certs := range map[string][]string{
		"empty":           {""},
		"not base64url":   {leaf + "*"},
		"not certificate": {b64url([]byte{0x30, 0x03, 0x02, 0x01, 0x01})},
		"bad issuer":      {leaf, "%%%"},
		"too many":        many,
	} {
		rec := postLink(t, h, certs...)
		if rec.Code != http.StatusBadRequest || !strings.HasPrefix(rec.Body.String(), "Bad link") {
			t.Errorf("%s: HTTP %d: %s", name, rec.Code, rec.Body)
		}
	}
}

func TestAnalyzeBase64URL(t *testing.T) {
	h := newTestHandler(t, nil)
	h.client = &http.Client{Transport: noNet{t}}
	h.analysisCache = newRespCache[analyzeResponse](0)

	for name, c := range map[string]struct{ text, subject string }{
		"generated": {b64url(testIssue(t, "Base64url Root", nil, true, nil).cert.Raw), "CN = Base64url Root"},
		// No '-', '_' or padding: plain base64 parsing loses its last block
		"alphanumeric": {"MIHpMIGcoAMCAQICAQEwBQYDK2VwMA0xCzAJBgNVBAMMAkFCMB4XDTI2MTAyNjE2MDU1N1oXDTI2MTAyNzE2MDU1N1owDTELMAkGA1UEAwwCQUIwKjAFBgMrZXADIQCjODpDX0VRS5HG0xo2F7eji7eLkrdKAgGCjCxVU2jnSqMhMB8wHQYDVR0OBBYEFDPUGUxRXKIZfDOsNELkUuq66zItMAUGAytlcANBAOk6ezW0oJnNxX0xyHwf74J9VUOQzdK6aHoFWbM7u43ZJNOmva7MJizcDqAoipyHU0T7Dn46mDNgWG0YjWNQbAw", "CN = AB"},
	} {
		rec := httptest.NewRecorder()
		h.analyze(rec, httptest.NewRequest(http.MethodPost, "/api/analyze", strings.NewReader(c.text+"\n")))
		var resp analyzeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: HTTP %d: %s", name, rec.Code, rec.Body)
		}
		if len(resp.Chain) != 1 || resp.Chain[0].Subject != c.subject {
			t.Errorf("%s: chain of %d: %s", name, len(resp.Chain), resp.Verify.Message)
		}
	}
}
