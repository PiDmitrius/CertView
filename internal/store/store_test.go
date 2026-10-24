package store

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestSHA256BackfillAndLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certview.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	crl := []byte("legacy crl der")
	_, err = legacy.Exec(`
		CREATE TABLE crls (
			id          INTEGER PRIMARY KEY,
			issuer      TEXT    NOT NULL,
			url         TEXT    NOT NULL UNIQUE,
			der         BLOB   NOT NULL,
			this_update INTEGER NOT NULL,
			next_update INTEGER NOT NULL,
			created_at  INTEGER NOT NULL
		);
		INSERT INTO crls (issuer, url, der, this_update, next_update, created_at)
		VALUES ('CA', 'http://example.test/ca.crl', ?, 0, 0, 0);`, crl)
	legacy.Close()
	if err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got, err := s.FindDERBySHA256(SHA256Hex(crl))
	if err != nil || !bytes.Equal(got, crl) {
		t.Fatalf("backfilled CRL: got %q, %v", got, err)
	}

	ocsp := []byte("ocsp der")
	if err := s.SaveOCSP("AB", "http://example.test/ocsp", "good", ocsp, time.Now(), time.Time{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !s.HasDER(SHA256Hex(ocsp)) {
		t.Fatal("saved OCSP response not found by sha256")
	}
	if s.HasDER(SHA256Hex([]byte("missing"))) {
		t.Fatal("unexpected hit for unknown sha256")
	}
}

func TestImportTrustedCertRespectsUntrust(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "certview.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	imp := func(serial string) bool {
		added, err := s.ImportTrustedCert("CN=R", "CN=R", serial, "", "", nil, []byte(serial), true, true, "ru-gov")
		if err != nil {
			t.Fatal(err)
		}
		return added
	}
	if !imp("01") {
		t.Fatal("new bundled root not added")
	}
	if err := s.SetTrusted(SHA256Hex([]byte("01")), false); err != nil {
		t.Fatal(err)
	}
	if imp("01") {
		t.Fatal("re-import overrode admin untrust")
	}
	if trusted, _ := s.IsCertTrusted(SHA256Hex([]byte("01"))); trusted {
		t.Fatal("admin untrust lost")
	}

	if err := s.SaveCert("CN=G", "CN=G", "02", "", "", nil, []byte("02"), true, true, "http://example.test/g.crt"); err != nil {
		t.Fatal(err)
	}
	if !imp("02") {
		t.Fatal("root fetched via AIA not trusted by bundle import")
	}
	if trusted, _ := s.IsCertTrusted(SHA256Hex([]byte("02"))); !trusted {
		t.Fatal("bundled root not trusted")
	}

	if err := s.SaveCert("CN=F", "CN=F", "01", "", "", nil, []byte("forged 01"), true, true, ""); err != nil {
		t.Fatal(err)
	}
	if trusted, _ := s.IsCertTrusted(SHA256Hex([]byte("forged 01"))); trusted {
		t.Fatal("serial collision inherited trust")
	}
}

func TestWithdrawBundleRoots(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "certview.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	imp := func(der string) bool {
		added, err := s.ImportTrustedCert("CN="+der, "CN="+der, der, "", "", nil, []byte(der), true, true, "mozilla")
		if err != nil {
			t.Fatal(err)
		}
		return added
	}
	trusted := func(der string) bool {
		ok, _ := s.IsCertTrusted(SHA256Hex([]byte(der)))
		return ok
	}
	imp("kept")
	imp("dropped")
	if _, err := s.ImportTrustedCert("CN=ru", "CN=ru", "ru", "", "", nil, []byte("ru"), true, true, "ru-gov"); err != nil {
		t.Fatal(err)
	}

	n, err := s.WithdrawBundleRoots("mozilla", []string{SHA256Hex([]byte("kept"))})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || !trusted("kept") || trusted("dropped") || !trusted("ru") {
		t.Fatalf("withdrew %d; kept=%v dropped=%v ru=%v", n, trusted("kept"), trusted("dropped"), trusted("ru"))
	}
	if !imp("dropped") || !trusted("dropped") {
		t.Fatal("root returning to the bundle not trusted again")
	}
}

func TestLegacySerialUniqueMigrates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certview.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`
		CREATE TABLE certs (
			id            INTEGER PRIMARY KEY,
			subject       TEXT    NOT NULL,
			issuer        TEXT    NOT NULL,
			serial        TEXT    NOT NULL UNIQUE,
			der           BLOB   NOT NULL,
			is_ca         INTEGER NOT NULL DEFAULT 0,
			is_self_signed INTEGER NOT NULL DEFAULT 0,
			source_url    TEXT,
			created_at    INTEGER NOT NULL
		);
		INSERT INTO certs (subject, issuer, serial, der, created_at) VALUES ('CN=A', 'CN=A', '00', 'root a', 0);`)
	legacy.Close()
	if err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SaveCert("CN=B", "CN=B", "00", "", "", nil, []byte("root b"), true, true, ""); err != nil {
		t.Fatal(err)
	}
	for _, der := range []string{"root a", "root b"} {
		if !s.HasDER(SHA256Hex([]byte(der))) {
			t.Fatalf("%s missing after migration", der)
		}
	}
}

func TestIssuerPoolExcludesUploads(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "certview.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	name := []byte("issuer name")
	if err := s.SaveCert("CN=I", "CN=R", "01", "AB", "", name, []byte("uploaded lookalike"), true, false, ""); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.FindIssuers(name, "AB", 8, 8); len(c) != 1 || c[0].Pool {
		t.Fatalf("uploaded certificate: got %+v, want one non-pool candidate", c)
	}
	if err := s.SavePoolCert("CN=I", "CN=R", "02", "AB", "", name, []byte("bundled"), true, false, "ru-gov"); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.FindIssuers(name, "AB", 8, 8); len(c) != 2 || !c[0].Pool || string(c[0].DER) != "bundled" {
		t.Fatalf("bundled issuer not first in pool: %+v", c)
	}
}

func TestCRLStoredOncePerContent(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "certview.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next := time.Now().Add(time.Hour)
	crl := []byte("crl der")
	for _, url := range []string{"http://ca.test/a.crl", "http://ca.test/a.crl?1", "http://ca.test/a.crl?2"} {
		if err := s.SaveCRL("CN=CA", url, crl, time.Now(), next); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := s.db.QueryRow("SELECT count(*) FROM crls").Scan(&n); err != nil || n != 1 {
		t.Fatalf("stored CRL rows: %d, %v", n, err)
	}
	for _, url := range []string{"http://ca.test/a.crl", "http://ca.test/a.crl?2"} {
		if der, _ := s.FindFreshCRL(url); !bytes.Equal(der, crl) {
			t.Fatalf("%s: got %q", url, der)
		}
	}
}

func TestRepairSHA1Once(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certview.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	der := []byte("root der")
	if err := s.SaveCert("CN=R", "CN=R", "00", "", "", nil, der, true, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE certs SET thumbprint_sha1 = 'WRONG'; PRAGMA user_version = 0"); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, _ := s.FindCertByThumbprint(sha1hex(der)); !bytes.Equal(got, der) {
		t.Fatal("thumbprint not repaired")
	}
}

func TestAnchoredJoinsPoolAndSHA256Lookup(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "certview.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	name := []byte("ca name")
	der := []byte("intermediate der")
	if err := s.SaveCert("CN=I", "CN=R", "05", "CD", "", name, der, true, false, "tls"); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.FindIssuers(name, "CD", 8, 8); len(c) != 1 || c[0].Pool {
		t.Fatal("archived certificate in the issuer pool")
	}
	if err := s.SavePoolCert("CN=I", "CN=R", "05", "CD", "", name, der, true, false, ""); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.FindIssuers(name, "CD", 8, 8); len(c) != 1 || !c[0].Pool {
		t.Fatal("anchored CA not in the issuer pool")
	}
	if got, _ := s.FindCertByThumbprint(SHA256Hex(der)); !bytes.Equal(got, der) {
		t.Fatal("not found by SHA-256 thumbprint")
	}
	if got, _ := s.FindCertByThumbprint(sha1hex(der)); !bytes.Equal(got, der) {
		t.Fatal("not found by SHA-1 thumbprint")
	}
}

func TestArchiveIssuersOldestAndNewest(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "certview.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 10; i++ {
		der := []byte{byte(i)}
		if err := s.SaveCert("CN=I", "CN=R", "01", "EE", "", []byte("n"), der, true, false, ""); err != nil {
			t.Fatal(err)
		}
		other := []byte{byte(100 + i)}
		if err := s.SaveCert("CN=X", "CN=R", "01", "EE", "", []byte("other"), other, true, false, ""); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.FindIssuers([]byte("n"), "EE", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]byte{{0}, {1}, {9}, {8}}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i].DER, want[i]) || got[i].Pool {
			t.Fatalf("candidate %d: got %+v, want %v", i, got[i], want[i])
		}
	}
}

func TestOCSPAndCRLDoNotAccumulate(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "certview.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	count := func(table string) (n int) {
		if err := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return
	}

	for i, der := range []string{"r1", "r2", "r3"} {
		if err := s.SaveOCSP("AA", "http://ocsp.test", "good", []byte(der), now, now.Add(time.Duration(i+1)*time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveOCSP("BB", "http://ocsp.test", "good", []byte("old"), now.Add(-2*time.Hour), now.Add(-time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveOCSP("CC", "http://ocsp.test", "good", []byte("c"), now, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if n := count("ocsp_responses"); n != 2 {
		t.Fatalf("%d OCSP responses kept, want the latest for AA and CC", n)
	}

	if err := s.SaveCRL("CN=CA", "", []byte("crl1"), now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCRL("CN=CA", "http://crl.test/a", []byte("crl2"), now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCRL("CN=CA", "http://crl.test/b", []byte("crl3"), now.Add(time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := count("crls"); n != 2 {
		t.Fatalf("%d CRLs kept, want the two a URL maps to", n)
	}
}
