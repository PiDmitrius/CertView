package trustbundle

import (
	"testing"

	"github.com/PiDmitrius/certview/internal/pki"
)

func TestBundledRootsVerifyThemselves(t *testing.T) {
	ctx, err := pki.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()

	for name, data := range map[string][]byte{"mozilla": mozillaPEM, "ru-gov": russianPEM} {
		roots := 0
		for _, block := range splitPEM(data) {
			info, err := ctx.ParseCertInfo(block)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !info.IsSelfSigned {
				continue
			}
			roots++
			vr, err := ctx.Verify(info.DER, [][]byte{info.DER}, nil)
			if err != nil {
				t.Fatalf("%s %s: %v", name, info.Subject, err)
			}
			if vr.ChainStatus != "ok" {
				t.Errorf("%s %s: %s (%s)", name, info.Subject, vr.ChainStatus, vr.ChainErrMsg)
			}
		}
		if roots == 0 {
			t.Fatalf("%s: no roots", name)
		}
	}
}
