package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PiDmitrius/certview/internal/pki"
	"github.com/PiDmitrius/certview/internal/store"
)

// fakeNet serves CRL and OCSP fetches from memory by URL.
type fakeNet map[string]func(req *http.Request) []byte

func (n fakeNet) RoundTrip(req *http.Request) (*http.Response, error) {
	serve, ok := n[req.URL.String()]
	if !ok {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	}
	body := serve(req)
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)), Header: http.Header{}, Request: req}, nil
}

func newTestHandler(t *testing.T, net fakeNet) *handler {
	t.Helper()
	ctx, err := pki.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctx.Close() })
	st, err := store.Open(filepath.Join(t.TempDir(), "certview.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &handler{ctx: ctx, store: st, client: &http.Client{Transport: net}}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var testSerial int64 = 100

// testIssue issues a certificate from parent, or a self-signed one when
// parent is nil; edit adjusts the template.
func testIssue(t *testing.T, cn string, parent *testCA, isCA bool, edit func(*x509.Certificate)) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	testSerial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(testSerial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	if edit != nil {
		edit(tmpl)
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

// analyzeWith analyzes leaf with certs as the certificates the analysis holds.
func analyzeWith(t *testing.T, h *handler, leaf []byte, certs ...[]byte) *analyzeResponse {
	t.Helper()
	var bag []bagCert
	for _, der := range certs {
		info, err := h.ctx.ParseCertInfo(der)
		if err != nil {
			t.Fatal(err)
		}
		bag = append(bag, bagCert{info: info, source: "test"})
	}
	resp, err := h.analyzeData(context.Background(), reqLog{}, leaf, bag, false)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestRootWithBadSignatureFailsChain(t *testing.T) {
	root := testIssue(t, "Root", nil, true, nil)
	leaf := testIssue(t, "Leaf", root, false, nil)

	if resp := analyzeWith(t, newTestHandler(t, fakeNet{}), leaf.cert.Raw, root.cert.Raw); resp.Verify.Status != "ok" {
		t.Fatalf("intact root: chain %s: %s", resp.Verify.Status, resp.Verify.Message)
	}

	bad := bytes.Clone(root.cert.Raw)
	bad[len(bad)-1] ^= 1
	if resp := analyzeWith(t, newTestHandler(t, fakeNet{}), leaf.cert.Raw, bad); resp.Verify.Status == "ok" {
		t.Fatal("root with a bad signature verified")
	}
}

// testChain issues a chain of n certificates, leaf first, ending at a root.
func testChain(t *testing.T, n int) [][]byte {
	t.Helper()
	ca := testIssue(t, "Depth Root", nil, true, nil)
	ders := [][]byte{ca.cert.Raw}
	for i := 1; i < n-1; i++ {
		ca = testIssue(t, fmt.Sprintf("Depth CA %d", i), ca, true, nil)
		ders = append([][]byte{ca.cert.Raw}, ders...)
	}
	leaf := testIssue(t, "Depth Leaf", ca, false, nil)
	return append([][]byte{leaf.cert.Raw}, ders...)
}

func TestDepthWarningOnlyWithoutRoot(t *testing.T) {
	hasWarning := func(resp *analyzeResponse) bool {
		for _, w := range resp.Warnings {
			if w == "Chain depth limit reached" {
				return true
			}
		}
		return false
	}

	full := testChain(t, maxChainDepth)
	resp := analyzeWith(t, newTestHandler(t, fakeNet{}), full[0], full[1:]...)
	if len(resp.Chain) != maxChainDepth || hasWarning(resp) {
		t.Fatalf("chain of %d ending at a root: %d certs, warnings %v", maxChainDepth, len(resp.Chain), resp.Warnings)
	}

	long := testChain(t, maxChainDepth+1)
	resp = analyzeWith(t, newTestHandler(t, fakeNet{}), long[0], long[1:]...)
	if len(resp.Chain) != maxChainDepth || !hasWarning(resp) {
		t.Fatalf("chain of %d: %d certs, warnings %v", maxChainDepth+1, len(resp.Chain), resp.Warnings)
	}
}
