package digest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/zeebo/blake3"
)

// KelDigestAtSeq returns Blake3-256 Matter qb64 (code E) over canonical KEL bytes through seq.
func KelDigestAtSeq(events []map[string]interface{}, seq int) (string, error) {
	filtered, err := eventsUpToSeq(events, seq)
	if err != nil {
		return "", err
	}
	raw, err := canonicalKELBytes(filtered)
	if err != nil {
		return "", err
	}
	sum := blake3.Sum256(raw)
	return matterFixedQB64("E", sum[:]), nil
}

func matterFixedQB64(code string, raw []byte) string {
	ps := (3 - (len(raw) % 3)) % 3
	padded := make([]byte, ps+len(raw))
	copy(padded[ps:], raw)
	b64 := base64URLEncode(padded)
	return code + b64[len(code)%4:]
}

func base64URLEncode(data []byte) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, 0, (len(data)*4+2)/3)
	for i := 0; i < len(data); i += 3 {
		var n uint32
		remain := len(data) - i
		switch {
		case remain >= 3:
			n = uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
			out = append(out, table[n>>18&63], table[n>>12&63], table[n>>6&63], table[n&63])
		case remain == 2:
			n = uint32(data[i])<<16 | uint32(data[i+1])<<8
			out = append(out, table[n>>18&63], table[n>>12&63], table[n>>6&63])
		default:
			n = uint32(data[i]) << 16
			out = append(out, table[n>>18&63], table[n>>12&63])
		}
	}
	return string(out)
}

func eventsUpToSeq(events []map[string]interface{}, seq int) ([]map[string]interface{}, error) {
	out := make([]map[string]interface{}, 0, len(events))
	for _, ev := range events {
		if eventSeq(ev) <= seq {
			out = append(out, ev)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no events at or before seq %d", seq)
	}
	sort.Slice(out, func(i, j int) bool { return eventSeq(out[i]) < eventSeq(out[j]) })
	return out, nil
}

func eventSeq(ev map[string]interface{}) int {
	switch v := ev["s"].(type) {
	case string:
		n, _ := strconv.Atoi(v)
		return n
	case float64:
		return int(v)
	default:
		return -1
	}
}

func canonicalKELBytes(events []map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, ev := range events {
		if i > 0 {
			buf.WriteByte(',')
		}
		b, err := json.Marshal(ev)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}

func CurrentSeq(events []map[string]interface{}) int {
	max := -1
	for _, ev := range events {
		if s := eventSeq(ev); s > max {
			max = s
		}
	}
	return max
}