// Command repair-sequences reports key events this witness stored at the
// wrong place while it read KERI's hexadecimal sequence numbers as decimal. It
// only reports: the repair itself runs inside the server at start, before it
// listens, with WW_REPAIR_SEQUENCES=apply, so nothing else writes meanwhile.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/grapeid/sp-witness-watcher/internal/store"
)

func main() {
	dir := flag.String("data", os.Getenv("WW_DATA_DIR"), "the witness's data directory")
	flag.Parse()
	if *dir == "" {
		log.Fatal("name the data directory with -data or WW_DATA_DIR")
	}
	st, err := store.Open(*dir)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	found, err := st.RepairSequences(false)
	if err != nil {
		log.Fatal(err)
	}
	if len(found) == 0 {
		fmt.Println("every stored event is at its own place, and there are no conflict rows")
		return
	}
	for _, r := range found {
		fmt.Printf("%s misplaced=%d conflicts=%d missing=%v\n", r.AID, r.Misplaced, r.Conflicts, r.Missing)
	}
	fmt.Println("nothing changed; to repair, restart the server with WW_REPAIR_SEQUENCES=apply")
}
