package pki

import (
	"errors"
	"slices"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// idpScope is the issuingDistributionPoint of a CRL (RFC 5280 §5.2.5).
type idpScope struct {
	HasDP       bool     // distributionPoint present
	URIs        []string // its fullName URIs
	OnlyUser    bool
	OnlyCA      bool
	OnlyAttr    bool
	SomeReasons bool
	Indirect    bool
}

// covers reports whether the CRL's scope includes a certificate with these
// CRL distribution points (RFC 5280 §6.3.3 b): its distributionPoint names
// one of them, its certificate kind fits, and it covers all reasons of the
// certificate's own issuer.
func (i *idpScope) covers(cdpURLs []string, isCA bool) bool {
	if i.SomeReasons || i.Indirect || i.OnlyAttr || i.OnlyUser && isCA || i.OnlyCA && !isCA {
		return false
	}
	if !i.HasDP {
		return true
	}
	for _, u := range i.URIs {
		if slices.Contains(cdpURLs, u) {
			return true
		}
	}
	return false
}

var oidIDP = []byte{0x55, 0x1d, 0x1c} // 2.5.29.28

// parseIDP reads the issuingDistributionPoint of a DER CRL, skipping its
// revoked certificates unparsed; nil without one.
func parseIDP(crl []byte) (*idpScope, error) {
	errMalformed := errors.New("malformed CRL")
	input := cryptobyte.String(crl)
	var list, tbs cryptobyte.String
	if !input.ReadASN1(&list, cbasn1.SEQUENCE) || !list.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil, errMalformed
	}
	var exts cryptobyte.String
	found := false
	for !tbs.Empty() {
		var elem cryptobyte.String
		var tag cbasn1.Tag
		if !tbs.ReadAnyASN1(&elem, &tag) {
			return nil, errMalformed
		}
		if tag == cbasn1.Tag(0).Constructed().ContextSpecific() {
			if !elem.ReadASN1(&exts, cbasn1.SEQUENCE) {
				return nil, errMalformed
			}
			found = true
		}
	}
	if !found {
		return nil, nil
	}
	for !exts.Empty() {
		var ext, oid, value cryptobyte.String
		if !exts.ReadASN1(&ext, cbasn1.SEQUENCE) || !ext.ReadASN1(&oid, cbasn1.OBJECT_IDENTIFIER) ||
			!ext.SkipOptionalASN1(cbasn1.BOOLEAN) || !ext.ReadASN1(&value, cbasn1.OCTET_STRING) {
			return nil, errMalformed
		}
		if string(oid) == string(oidIDP) {
			return parseIDPValue(value)
		}
	}
	return nil, nil
}

func parseIDPValue(value cryptobyte.String) (*idpScope, error) {
	errMalformed := errors.New("malformed issuingDistributionPoint")
	var seq cryptobyte.String
	if !value.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, errMalformed
	}
	idp := &idpScope{}
	flag := func(field cryptobyte.String) bool { return len(field) == 1 && field[0] != 0 }
	for !seq.Empty() {
		var field cryptobyte.String
		var tag cbasn1.Tag
		if !seq.ReadAnyASN1(&field, &tag) {
			return nil, errMalformed
		}
		switch tag {
		case cbasn1.Tag(0).Constructed().ContextSpecific():
			idp.HasDP = true
			var names cryptobyte.String
			// Only a fullName is matched; nameRelativeToCRLIssuer leaves URIs empty
			if field.ReadASN1(&names, cbasn1.Tag(0).Constructed().ContextSpecific()) {
				for !names.Empty() {
					var name cryptobyte.String
					var nameTag cbasn1.Tag
					if !names.ReadAnyASN1(&name, &nameTag) {
						return nil, errMalformed
					}
					if nameTag == cbasn1.Tag(6).ContextSpecific() {
						idp.URIs = append(idp.URIs, string(name))
					}
				}
			}
		case cbasn1.Tag(1).ContextSpecific():
			idp.OnlyUser = flag(field)
		case cbasn1.Tag(2).ContextSpecific():
			idp.OnlyCA = flag(field)
		case cbasn1.Tag(3).ContextSpecific():
			idp.SomeReasons = true
		case cbasn1.Tag(4).ContextSpecific():
			idp.Indirect = flag(field)
		case cbasn1.Tag(5).ContextSpecific():
			idp.OnlyAttr = flag(field)
		}
	}
	return idp, nil
}
