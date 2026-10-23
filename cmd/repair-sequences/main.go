// Command repair-sequences reports, and with -apply repairs, key events this
// witness stored at the wrong place while it read KERI's hexadecimal sequence
// numbers as decimal. It reports by default and changes nothing; conflict rows
// are reported, never deleted.
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
	apply := flag.Bool("apply", false, "move misplaced events to their own places and recompute digests")
	flag.Parse()
	if *dir == "" {
		log.Fatal("name the data directory with -data or WW_DATA_DIR")
	}
	st, err := store.Open(*dir)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	found, err := st.RepairSequences(*apply)
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
	if *apply {
		fmt.Println("misplaced events moved; conflict rows left for a person to judge")
	} else {
		fmt.Println("nothing changed; run with -apply to move misplaced events")
	}
}
