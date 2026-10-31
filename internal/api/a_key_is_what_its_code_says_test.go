package api

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

const qb64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// flipChar flips the given bits of the i'th character of a qb64 value.
func flipChar(s string, i, bits int) string {
	return s[:i] + string(qb64Alphabet[strings.IndexByte(qb64Alphabet, s[i])^bits]) + s[i+1:]
}

func icpDeclaring(t *testing.T, key string) (raw []byte, parsed map[string]interface{}) {
	t.Helper()
	raw = []byte(`{"v":"KERI10JSON000120_","t":"icp","d":"EAAAtestevent","i":"EAAAtestevent","s":"0","k":["` + key + `"]}`)
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	return raw, parsed
}

// A Blake3 digest is code E. Read by its length alone, it was an Ed25519 key,
// so an event could declare one and be witnessed on a signature by the key
// whose bytes the digest happened to be.
func TestADigestIsNotAnEventsKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	raw, parsed := icpDeclaring(t, "E"+qb64Key(pub)[1:])
	if err := verifyControllerSignature(raw, parsed, cesrSig(ed25519.Sign(priv, raw)), nil, nil); err == nil {
		t.Fatal("an event declaring a digest as its key was witnessed")
	}
}

// The code D stands for one zero byte, and covers 6 of its 8 bits; the other
// 2 are in the next character. Unchecked, every key had four spellings.
func TestAKeyWithLeadBitsIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	raw, parsed := icpDeclaring(t, flipChar(qb64Key(pub), 1, 0x10))
	if err := verifyControllerSignature(raw, parsed, cesrSig(ed25519.Sign(priv, raw)), nil, nil); err == nil {
		t.Fatal("a key whose lead bits are not zero was read as the key")
	}
}

// The code 0B stands for two zero bytes, and covers 12 of their 16 bits; the
// other 4 are in the third character. Unchecked, every signature had sixteen
// spellings, each stored as a different string.
func TestASignatureWithLeadBitsIsRefused(t *testing.T) {
	raw, parsed, sig, _ := signedEvent(t)
	for bits := 0x04; bits < 0x40; bits += 0x04 {
		if err := verifyControllerSignature(raw, parsed, flipChar(sig, 2, bits), nil, nil); err == nil {
			t.Fatalf("a signature with lead bits %x was accepted", bits)
		}
	}
}
