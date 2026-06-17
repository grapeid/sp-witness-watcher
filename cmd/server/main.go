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