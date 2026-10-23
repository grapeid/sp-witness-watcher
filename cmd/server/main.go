package main

import (
	"log"
	"net/http"
	"os"

	"github.com/grapeid/sp-witness-watcher/internal/api"
	"github.com/grapeid/sp-witness-watcher/internal/signer"
	"github.com/grapeid/sp-witness-watcher/internal/store"
)

func main() {
	dataDir := os.Getenv("WW_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8092"
	}
	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	st, err := store.Open(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	// Events stored while sequence numbers were read as decimal are repaired
	// here, before the server listens, so nothing else writes meanwhile.
	// "report" lists them; "apply" moves them, keeping a record of each move.
	if mode := os.Getenv("WW_REPAIR_SEQUENCES"); mode == "report" || mode == "apply" {
		found, err := st.RepairSequences(mode == "apply")
		if err != nil {
			log.Fatalf("[sp-witness-watcher] repairing sequence numbers: %v", err)
		}
		for _, r := range found {
			log.Printf("[sp-witness-watcher] sequences %s: %s misplaced=%d conflicts=%d missing=%v", mode, r.AID, r.Misplaced, r.Conflicts, r.Missing)
		}
		log.Printf("[sp-witness-watcher] sequences %s: %d identities", mode, len(found))
	}

	id, err := signer.LoadOrCreate(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[sp-witness-watcher] service AID=%s", id.AID)

	srv := api.New(st, id)
	addr := host + ":" + port
	log.Printf("[sp-witness-watcher] listening on http://%s", addr)
	log.Printf("[sp-witness-watcher] witness: POST /witness/event GET /witness/kel/{aid}")
	log.Printf("[sp-witness-watcher] watcher: GET /public/kel-digest POST /enroll")
	if err := http.ListenAndServe(addr, srv.Router()); err != nil {
		log.Fatal(err)
	}
}