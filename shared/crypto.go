package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"io"
	"strings"
)

const (
	NonceSize     = 12
	SIDSize       = 8
	LabelSegLen   = 30
	GCMTagSize    = 16
	MinE2EBlobLen = NonceSize + GCMTagSize

	DirUpload   = "u"
	DirPoll     = "p"
	DirJoin     = "j"
	DirNames    = "n"
	DirLeave    = "l"
	RespOK      = "ok"
	RespDup     = "dup"
	RespUnreg   = "unreg"
	RespBad     = "bad"
	RespNoop    = "noop"
)

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

func SplitToLabels(s string, segLen int) []string {
	if segLen <= 0 {
		return []string{s}
	}
	out := make([]string, 0, (len(s)+segLen-1)/segLen)
	for i := 0; i < len(s); i += segLen {
		end := i + segLen
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

func B32Encode(data []byte) string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data))
}

func B32Decode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "")
	u := strings.ToUpper(s)
	if m := len(u) % 8; m != 0 {
		u += strings.Repeat("=", 8-m)
	}
	return base32.StdEncoding.DecodeString(u)
}

func B64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func B64URLDecode(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

func AESGCMEncrypt(key, nonce, data, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nonce, data, aad), nil
}

func AESGCMDecrypt(key, nonce, data, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, data, aad)
}

// RouteID derives an 8-byte routing identifier from the group name.
// Used in DNS labels for session matching — cannot be reversed to recover the group name.
func RouteID(group []byte) []byte {
	mac := hmac.New(sha256.New, []byte("dnsay-route"))
	mac.Write(group)
	return mac.Sum(nil)[:8]
}

// DeriveKey derives a 32-byte AES-256 key from the group name.
// Uses a different HMAC key than RouteID for domain separation.
func DeriveKey(group []byte) []byte {
	mac := hmac.New(sha256.New, []byte("dnsay-key-v1"))
	mac.Write(group)
	return mac.Sum(nil)
}
