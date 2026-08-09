package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Identity holds the service KERI-style AID and signing keys (OQ-WW1: one AID for both roles).
type Identity struct {
	AID        string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// LoadOrCreate loads service identity from dataDir or generates a new one.
func LoadOrCreate(dataDir string) (*Identity, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "service_identity.json")
	if b, err := os.ReadFile(path); err == nil {
		var raw struct {
			AID         string `json:"aid"`
			PubB64      string `json:"public_key_b64"`
			PrivSeedB64 string `json:"private_seed_b64"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, err
		}
		pub, _ := base64.StdEncoding.DecodeString(raw.PubB64)
		seed, _ := base64.StdEncoding.DecodeString(raw.PrivSeedB64)
		if len(pub) == ed25519.PublicKeySize && len(seed) == ed25519.SeedSize {
			// The identifier is DERIVED, never read from the file. A
			// non-transferable identifier IS its verifying key, so taking the
			// stored value on trust would let the file name a key it does not
			// hold — the one thing this kind of identifier exists to prevent.
			// Deriving it also lets an instance created before this keep its
			// keys and simply report the correct identifier, with no migration.
			derived := ed25519.NewKeyFromSeed(seed)
			derivedPub := derived.Public().(ed25519.PublicKey)
			return &Identity{
				AID: NonTransferableAID(derivedPub), PublicKey: derivedPub,
				PrivateKey: derived,
			}, nil
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	aid := NonTransferableAID(pub)
	id := &Identity{AID: aid, PublicKey: pub, PrivateKey: priv}
	seed := priv.Seed()
	out, _ := json.MarshalIndent(map[string]string{
		"aid":              aid,
		"public_key_b64":   base64.StdEncoding.EncodeToString(pub),
		"private_seed_b64": base64.StdEncoding.EncodeToString(seed),
	}, "", "  ")
	if err := os.WriteFile(path, out, 0600); err != nil {
		return nil, err
	}
	return id, nil
}

// NonTransferableAID encodes an Ed25519 public key as a CESR non-transferable
// identifier (code "B").
//
// What stood here was "E" + base64url(key), which is not a CESR identifier at
// all: "E" denotes a Blake3 digest, and this is not a digest of anything. It was
// the right length by coincidence and unparseable by every KERI implementation,
// including the one that has to verify our receipts.
//
// The encoding is not a concatenation. A 1-character code needs one leading pad
// byte so the raw bytes align to base64, and the leading character of that
// encoding is then replaced by the code.
func NonTransferableAID(pub ed25519.PublicKey) string {
	padded := make([]byte, 1+len(pub))
	copy(padded[1:], pub)
	return "B" + base64.RawURLEncoding.EncodeToString(padded)[1:]
}

// CESRSignature signs payload and returns a CESR qb64 signature (code "0B").
//
// A 2-character code needs two leading pad bytes, and the two leading
// characters of the encoding are replaced by the code.
func (id *Identity) CESRSignature(payload []byte) string {
	sig := ed25519.Sign(id.PrivateKey, payload)
	padded := make([]byte, 2+len(sig))
	copy(padded[2:], sig)
	return "0B" + base64.RawURLEncoding.EncodeToString(padded)[2:]
}

// Sign returns base64url signature over payload bytes.
func (id *Identity) Sign(payload []byte) string {
	sig := ed25519.Sign(id.PrivateKey, payload)
	return base64.RawURLEncoding.EncodeToString(sig)
}

// Verify checks an ed25519 signature.
func Verify(pub ed25519.PublicKey, payload []byte, sigB64 string) error {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}
