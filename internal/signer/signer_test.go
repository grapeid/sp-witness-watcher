package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// A witness is named by a non-transferable identifier, which IS its verifying
// key. That is the whole reason a receipt can be checked by anyone holding the
// key event: the identifier written there is already the key, so there is
// nothing to look up and nothing in the middle of a lookup that could answer
// wrongly.
//
// The version this replaces produced "E" + base64url(key). "E" denotes a Blake3
// digest, so that claimed to be a digest of something while actually being the
// key — unparseable by every KERI implementation, including the one that has to
// verify what we sign.
func TestTheIdentifierIsTheVerifyingKey(t *testing.T) {
	id, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id.AID, "B") || len(id.AID) != 44 {
		t.Fatalf("identifier is %q (%d chars), want a 44-character B-prefixed identifier",
			id.AID, len(id.AID))
	}
	// Recover the key from the identifier the way any verifier would: one pad
	// character back on, decode, drop the pad byte.
	raw, err := base64.RawURLEncoding.DecodeString("A" + id.AID[1:])
	if err != nil {
		t.Fatalf("identifier is not valid base64url: %v", err)
	}
	if len(raw) != 33 {
		t.Fatalf("identifier decodes to %d bytes, want 33", len(raw))
	}
	if string(raw[1:]) != string(id.PublicKey) {
		t.Fatal("the identifier does not carry this service's public key")
	}
}

// And a receipt made under it verifies against that key alone.
func TestAReceiptVerifiesAgainstTheIdentifier(t *testing.T) {
	id, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const said = "EEventSAID0123456789ABCDEFGHIJKLMNOPQRSTUVW"
	qb64 := id.CESRSignature([]byte(said))
	if !strings.HasPrefix(qb64, "0B") || len(qb64) != 88 {
		t.Fatalf("signature is %q (%d chars), want an 88-character 0B signature", qb64, len(qb64))
	}
	sig, err := base64.RawURLEncoding.DecodeString("AA" + qb64[2:])
	if err != nil {
		t.Fatalf("signature is not valid base64url: %v", err)
	}
	if !ed25519.Verify(id.PublicKey, []byte(said), sig[2:]) {
		t.Fatal("the receipt does not verify against the key its identifier names")
	}
	if ed25519.Verify(id.PublicKey, []byte("EOtherEvent000000000000000000000000000000x"), sig[2:]) {
		t.Fatal("the receipt verifies for an event it was not issued for")
	}
}

// An instance that already exists keeps its keys and starts reporting the
// correct identifier. Without this every deployed witness would have to
// regenerate its identity, and a witness that changes identity invalidates
// every receipt it has issued.
func TestAnExistingIdentityKeepsItsKeysAndGainsACorrectIdentifier(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	// A file in the old shape, naming the old style of identifier.
	old := `{"aid":"E` + base64.RawURLEncoding.EncodeToString(pub)[:43] + `",` +
		`"public_key_b64":"` + base64.StdEncoding.EncodeToString(pub) + `",` +
		`"private_seed_b64":"` + base64.StdEncoding.EncodeToString(seed) + `"}`
	if err := os.WriteFile(dir+"/service_identity.json", []byte(old), 0600); err != nil {
		t.Fatal(err)
	}

	id, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("an existing identity could not be loaded: %v", err)
	}
	if string(id.PublicKey) != string(pub) {
		t.Fatal("the existing key was not kept")
	}
	if !strings.HasPrefix(id.AID, "B") {
		t.Fatalf("the stored identifier was used as-is: %q", id.AID)
	}
	if id.AID != NonTransferableAID(pub) {
		t.Fatal("the identifier is not the one this key derives")
	}
}
