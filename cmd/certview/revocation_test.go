package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// revocationOf analyzes leaf issued by root and returns the leaf's
// revocation status, empty when not determined, and the overall one.
func revocationOf(t *testing.T, net fakeNet, root, leaf *testCA) (string, *analyzeResponse) {
	t.Helper()
	resp := analyzeWith(t, newTestHandler(t, net), leaf.cert.Raw, root.cert.Raw)
	if resp.Verify.Status == "error" && resp.Verify.RevocationStatus != "revoked" {
		t.Fatalf("chain: %s", resp.Verify.Message)
	}
	status := ""
	if r := resp.Chain[0].Revocation; r != nil {
		status = r.Status
	}
	return status, resp
}

func ocspResponder(t *testing.T, root *testCA, tmpl ocsp.Response) func(*http.Request) []byte {
	return func(*http.Request) []byte {
		der, err := ocsp.CreateResponse(root.cert, root.cert, tmpl, root.key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
}

func TestOCSPShowsUnrevokedOnlyWhenGoodAndCurrent(t *testing.T) {
	root := testIssue(t, "OCSP Root", nil, true, nil)
	now := time.Now()
	for _, tc := range []struct {
		name string
		tmpl func(leaf *x509.Certificate) ocsp.Response
		want string
	}{
		{"good", func(leaf *x509.Certificate) ocsp.Response {
			return ocsp.Response{Status: ocsp.Good, SerialNumber: leaf.SerialNumber, ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour)}
		}, "not_revoked"},
		{"unknown", func(leaf *x509.Certificate) ocsp.Response {
			return ocsp.Response{Status: ocsp.Unknown, SerialNumber: leaf.SerialNumber, ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour)}
		}, ""},
		{"other certificate", func(leaf *x509.Certificate) ocsp.Response {
			return ocsp.Response{Status: ocsp.Good, SerialNumber: new(big.Int).Add(leaf.SerialNumber, big.NewInt(1000)), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour)}
		}, ""},
		{"expired", func(leaf *x509.Certificate) ocsp.Response {
			return ocsp.Response{Status: ocsp.Good, SerialNumber: leaf.SerialNumber, ThisUpdate: now.Add(-48 * time.Hour), NextUpdate: now.Add(-24 * time.Hour)}
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := "http://ocsp.test/" + strings.ReplaceAll(tc.name, " ", "-")
			leaf := testIssue(t, "Leaf "+tc.name, root, false, func(c *x509.Certificate) { c.OCSPServer = []string{url} })
			status, resp := revocationOf(t, fakeNet{url: ocspResponder(t, root, tc.tmpl(leaf.cert))}, root, leaf)
			if status != tc.want {
				t.Fatalf("revocation %q, want %q (%s)", status, tc.want, resp.Verify.RevocationMsg)
			}
			if tc.want == "" && resp.Verify.RevocationStatus != "incomplete" {
				t.Fatalf("overall revocation %q, want incomplete", resp.Verify.RevocationStatus)
			}
		})
	}
}

func TestScopedCRLShowsRevokedNotUnrevoked(t *testing.T) {
	root := testIssue(t, "CRL Root", nil, true, nil)
	deltaIndicator, err := asn1.Marshal(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	// issuingDistributionPoint with the CRL's own URI as distributionPoint
	idp := func(uri string) []byte {
		gn := append([]byte{0x86, byte(len(uri))}, uri...)
		full := append([]byte{0xA0, byte(len(gn))}, gn...)
		dp := append([]byte{0xA0, byte(len(full))}, full...)
		return append([]byte{0x30, byte(len(dp))}, dp...)
	}
	for _, tc := range []struct {
		name    string
		ext     func(url string) []pkix.Extension
		revoked bool
		want    string
	}{
		{"complete", func(string) []pkix.Extension { return nil }, false, "not_revoked"},
		{"delta", func(string) []pkix.Extension {
			return []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: deltaIndicator}}
		}, false, ""},
		{"idp", func(url string) []pkix.Extension {
			return []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: idp(url)}}
		}, false, ""},
		{"idp revoked", func(url string) []pkix.Extension {
			return []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: idp(url)}}
		}, true, "revoked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := "http://crl.test/" + strings.ReplaceAll(tc.name, " ", "-") + ".crl"
			leaf := testIssue(t, "Leaf "+tc.name, root, false, func(c *x509.Certificate) { c.CRLDistributionPoints = []string{url} })
			list := &x509.RevocationList{
				Number:          big.NewInt(2),
				ThisUpdate:      time.Now().Add(-time.Hour),
				NextUpdate:      time.Now().Add(time.Hour),
				ExtraExtensions: tc.ext(url),
			}
			if tc.revoked {
				list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: leaf.cert.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)}}
			}
			der, err := x509.CreateRevocationList(rand.Reader, list, root.cert, root.key)
			if err != nil {
				t.Fatal(err)
			}
			status, resp := revocationOf(t, fakeNet{url: func(*http.Request) []byte { return der }}, root, leaf)
			if status != tc.want {
				t.Fatalf("revocation %q, want %q (%s)", status, tc.want, resp.Verify.RevocationMsg)
			}
			if tc.want == "" && !strings.Contains(resp.Verify.RevocationMsg, "CRL") {
				t.Fatalf("no CRL scope explanation: %q", resp.Verify.RevocationMsg)
			}
		})
	}
}

func TestOCSPRevocationDateAndReason(t *testing.T) {
	root := testIssue(t, "OCSP Root", nil, true, nil)
	url := "http://ocsp.test/revoked"
	leaf := testIssue(t, "Leaf revoked", root, false, func(c *x509.Certificate) { c.OCSPServer = []string{url} })
	revokedAt := time.Now().Add(-2 * time.Hour).Truncate(time.Second).UTC()
	tmpl := ocsp.Response{Status: ocsp.Revoked, SerialNumber: leaf.cert.SerialNumber,
		ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour),
		RevokedAt: revokedAt, RevocationReason: ocsp.KeyCompromise}

	status, resp := revocationOf(t, fakeNet{url: ocspResponder(t, root, tmpl)}, root, leaf)
	if status != "revoked" || resp.Verify.RevocationStatus != "revoked" {
		t.Fatalf("revocation %q, overall %q", status, resp.Verify.RevocationStatus)
	}
	want := revokedAt.Format(time.RFC3339)
	if r := resp.Chain[0].Revocation; r.RevokedAt != want || r.Reason != "keyCompromise" {
		t.Fatalf("certificate revocation %+v, want %s keyCompromise", r, want)
	}
	if o := resp.Chain[1].IssuedOCSPs; len(o) != 1 || o[0].RevokedAt != want || o[0].Reason != "keyCompromise" {
		t.Fatalf("OCSP response %+v", o)
	}
}
