package store

import (
	"errors"
	"time"
)

// EscrowLimit is how many events one identity may have held back at once,
// and EscrowLife how long one is held before it is dropped.
//
// EscrowTotalLimit bounds what is held back across every identity, of which
// EscrowReserved is kept for identities with history here beyond their
// inception: anybody can make identities of their own for nothing, and without
// the reserve enough of them would fill the escrow and leave an established
// identity's event nowhere to wait. EscrowPerSender bounds what one sender
// (by address) may have held back at once.
var (
	EscrowLimit      = 64
	EscrowTotalLimit = 10000
	EscrowReserved   = 2000
	EscrowPerSender  = 256
	EscrowLife       = 24 * time.Hour
	// EstablishedAfter is how long an identity's history beyond its
	// inception must have been held here before it counts as established:
	// long enough that identities made for the purpose cannot be readied in
	// time to fill the reserve.
	EstablishedAfter = 24 * time.Hour
)

// Now is the store's clock.
var Now = time.Now

// Established reports whether aid has history held here beyond its
// inception, received at least EstablishedAfter ago. Enrolment does not
// count, since anybody may enrol any identity, and this witness has no other
// agreement to witness one.
func (s *ServiceStore) Established(aid string) (bool, error) {
	cutoff := Now().UTC().Add(-EstablishedAfter).Format(time.RFC3339)
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM kel_events WHERE aid=? AND sequence_num >= 1 AND received_at <= ?`, aid, cutoff).Scan(&n)
	return n > 0, err
}

// ErrEscrowFull is an identity with as many events held back as it may have.
var ErrEscrowFull = errors.New("too many of this identity's events are waiting for the ones before them")

// Escrowed is an event held back until the event before it arrives.
type Escrowed struct {
	SAID      string
	RawB64    string
	Signature string
}

// EscrowEvent holds an event back until the one before it arrives, dropping
// any held longer than EscrowLife first.
//
// established is an identity with history here beyond its inception; sender
// is where the event came from.
func (s *ServiceStore) EscrowEvent(aid string, sn int, said, rawB64, sig, sender string, established bool) error {
	cutoff := time.Now().UTC().Add(-EscrowLife).Format(time.RFC3339)
	_, _ = s.db.Exec(`DELETE FROM escrowed_events WHERE received_at < ?`, cutoff)
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM escrowed_events WHERE aid=?`, aid).Scan(&n); err != nil {
		return err
	}
	if n >= EscrowLimit {
		return ErrEscrowFull
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM escrowed_events`).Scan(&total); err != nil {
		return err
	}
	limit := EscrowTotalLimit
	if !established {
		limit -= EscrowReserved
	}
	if total >= limit {
		return ErrEscrowFull
	}
	if sender != "" {
		var bySender int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM escrowed_events WHERE client_ip=?`, sender).Scan(&bySender); err != nil {
			return err
		}
		if bySender >= EscrowPerSender {
			return ErrEscrowFull
		}
	}
	_, err := s.db.Exec(`INSERT INTO escrowed_events (aid, sequence_num, said, raw_b64, cesr_signature, received_at, client_ip) VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(aid, said) DO NOTHING`, aid, sn, said, rawB64, sig, time.Now().UTC().Format(time.RFC3339), sender)
	return err
}

// EscrowedAt are the events held back for place sn.
func (s *ServiceStore) EscrowedAt(aid string, sn int) ([]Escrowed, error) {
	rows, err := s.db.Query(`SELECT said, raw_b64, cesr_signature FROM escrowed_events WHERE aid=? AND sequence_num=? ORDER BY received_at`, aid, sn)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Escrowed
	for rows.Next() {
		var e Escrowed
		if err := rows.Scan(&e.SAID, &e.RawB64, &e.Signature); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DropEscrowed stops holding an event back.
func (s *ServiceStore) DropEscrowed(aid, said string) {
	_, _ = s.db.Exec(`DELETE FROM escrowed_events WHERE aid=? AND said=?`, aid, said)
}

// RecordConflict records a disagreement about what is at a place.
func (s *ServiceStore) RecordConflict(aid string, sn int, what, said string) {
	_, _ = s.db.Exec(`INSERT INTO digest_conflicts (aid, sequence_num, digest_a, digest_b, detected_at) VALUES (?,?,?,?,?)`,
		aid, sn, what, said, time.Now().UTC().Format(time.RFC3339))
}
