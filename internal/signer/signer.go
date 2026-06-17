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
			AID       string `json:"aid"`
			PubB64    string `json:"public_key_b64"`
			PrivSeedB64 string `json:"private_seed_b64"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, err
		}
		pub, _ := base64.StdEncoding.DecodeString(raw.PubB64)
		seed, _ := base64.StdEncoding.DecodeString(raw.PrivSeedB64)
		if len(pub) == ed25519.PublicKeySize && len(seed) == ed25519.SeedSize {
			return &Identity{
				AID: raw.AID, PublicKey: ed25519.PublicKey(pub),
				PrivateKey: ed25519.NewKeyFromSeed(seed),
			}, nil
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	aid := "E" + base64.RawURLEncoding.EncodeToString(pub)[:43]
	id := &Identity{AID: aid, PublicKey: pub, PrivateKey: priv}
	seed := priv.Seed()
	out, _ := json.MarshalIndent(map[string]string{
		"aid": aid,
		"public_key_b64": base64.StdEncoding.EncodeToString(pub),
		"private_seed_b64": base64.StdEncoding.EncodeToString(seed),
	}, "", "  ")
	if err := os.WriteFile(path, out, 0600); err != nil {
		return nil, err
	}
	return id, nil
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