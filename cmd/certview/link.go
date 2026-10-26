package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/PiDmitrius/certview/internal/limits"
	"github.com/PiDmitrius/certview/internal/pki"
	"github.com/PiDmitrius/certview/internal/store"
)

// analyzeLink analyzes the certificates of a #cert= link: base64url DER, leaf
// first, the others offered as its issuers before AIA. None is stored.
func (h *handler) analyzeLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Certs []string `json:"certs"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, int64(maxChainDepth)*2*limits.CertSize)).Decode(&req); err != nil {
		http.Error(w, "Bad link: malformed request", http.StatusBadRequest)
		return
	}
	certs, err := h.parseLink(req.Certs)
	if err != nil {
		http.Error(w, "Bad link: "+err.Error(), http.StatusBadRequest)
		return
	}

	key := "link"
	for _, c := range certs {
		key += " " + store.SHA256Hex(c.DER)
	}
	resp, _, err := h.analysisCache.get(r.Context(), key, func() (*analyzeResponse, error) {
		return h.doAnalyzeLink(r.Context(), certs)
	})
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *handler) doAnalyzeLink(ctx context.Context, certs []*pki.CertInfo) (*analyzeResponse, error) {
	rl := reqLog{id: reqCounter.Add(1)}
	ctx, release, err := guardAnalysis(ctx, rl)
	if err != nil {
		return nil, err
	}
	defer release()
	var bag []bagCert
	for _, c := range certs[1:] {
		bag = append(bag, bagCert{c, sourceLink})
	}
	return h.analyzeData(ctx, rl, certs[0].DER, bag, true)
}

// parseLink decodes the certificates of a link, at most maxChainDepth.
func (h *handler) parseLink(values []string) ([]*pki.CertInfo, error) {
	if len(values) == 0 {
		return nil, errors.New("no certificate")
	}
	if len(values) > maxChainDepth {
		return nil, fmt.Errorf("%d certificates, limit %d", len(values), maxChainDepth)
	}
	var certs []*pki.CertInfo
	for i, v := range values {
		der, ok := decodeB64URL(v)
		if !ok {
			return nil, fmt.Errorf("certificate %d is not base64url DER", i+1)
		}
		if len(der) > limits.CertSize {
			return nil, fmt.Errorf("certificate %d too large: %d bytes, limit %d", i+1, len(der), limits.CertSize)
		}
		info, err := h.ctx.ParseCertInfo(der)
		if err != nil {
			return nil, fmt.Errorf("certificate %d is not a certificate", i+1)
		}
		certs = append(certs, info)
	}
	return certs, nil
}

// decodeB64URL decodes base64url DER, padded or not.
func decodeB64URL(s string) ([]byte, bool) {
	der, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	return der, err == nil && len(der) > 0 && der[0] == 0x30
}
