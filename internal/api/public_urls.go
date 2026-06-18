package api

import (
	"fmt"
	"os"
	"strings"
)

func instanceSuffix() string {
	n := strings.TrimSpace(os.Getenv("WW_INSTANCE"))
	if n != "" && n != "0" {
		return n
	}
	return "1"
}

func witnessEventURL() string {
	if base := strings.TrimRight(strings.TrimSpace(os.Getenv("WW_WITNESS_PUBLIC_URL")), "/"); base != "" {
		return base + "/witness/event"
	}
	return fmt.Sprintf("https://witness%s.grapeid.org/witness/event", instanceSuffix())
}

func watcherKelDigestURL() string {
	if base := strings.TrimRight(strings.TrimSpace(os.Getenv("WW_WATCHER_PUBLIC_URL")), "/"); base != "" {
		return base + "/public/kel-digest"
	}
	return fmt.Sprintf("https://watcher%s.grapeid.org/public/kel-digest", instanceSuffix())
}