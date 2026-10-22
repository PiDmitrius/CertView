package trustbundle

import (
	"bytes"
	_ "embed"
	"log"

	"github.com/PiDmitrius/certview/internal/pki"
	"github.com/PiDmitrius/certview/internal/store"
)

//go:embed mozilla.pem
var mozillaPEM []byte

//go:embed russian.pem
var russianPEM []byte

// ImportDefaults imports bundled CA certs on every start. Self-signed certs
// become trusted roots unless already imported from the same bundle, so an
// admin's untrust of a bundled root survives restarts; roots dropped from a
// bundle lose trust; intermediates join the pool of candidate issuers.
func ImportDefaults(ctx *pki.Context, st *store.Store) error {
	importBundle(ctx, st, mozillaPEM, "mozilla")
	importBundle(ctx, st, russianPEM, "ru-gov")
	return nil
}

func importBundle(ctx *pki.Context, st *store.Store, data []byte, source string) {
	var roots []string
	trustedCount := 0
	for _, block := range splitPEM(data) {
		info, err := ctx.ParseCertInfo(block)
		if err != nil {
			continue
		}
		if info.IsSelfSigned {
			roots = append(roots, store.SHA256Hex(info.DER))
			added, err := st.ImportTrustedCert(
				info.Subject, info.Issuer, info.Serial,
				info.SKI, info.AKI, info.SubjectNameDER,
				info.DER, info.IsCA, info.IsSelfSigned, source,
			)
			if err != nil {
				log.Printf("trustbundle: import trusted %s: %v", info.Subject, err)
				continue
			}
			if added {
				trustedCount++
			}
		} else {
			if err := st.SavePoolCert(
				info.Subject, info.Issuer, info.Serial,
				info.SKI, info.AKI, info.SubjectNameDER,
				info.DER, info.IsCA, info.IsSelfSigned, source,
			); err != nil {
				log.Printf("trustbundle: import intermediate %s: %v", info.Subject, err)
			}
		}
	}
	if len(roots) == 0 {
		log.Printf("trustbundle: no roots parsed from %s bundle", source)
		return
	}
	withdrawn, err := st.WithdrawBundleRoots(source, roots)
	if err != nil {
		log.Printf("trustbundle: withdraw %s roots: %v", source, err)
	}
	log.Printf("trustbundle: %s bundle: %d new trusted roots, %d withdrawn", source, trustedCount, withdrawn)
}

func splitPEM(data []byte) [][]byte {
	var blocks [][]byte
	begin := []byte("-----BEGIN CERTIFICATE-----")
	end := []byte("-----END CERTIFICATE-----")
	for {
		i := bytes.Index(data, begin)
		if i < 0 {
			break
		}
		j := bytes.Index(data[i:], end)
		if j < 0 {
			break
		}
		blocks = append(blocks, data[i:i+j+len(end)])
		data = data[i+j+len(end):]
	}
	return blocks
}
