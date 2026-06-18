// One-off helper: prints KelDigestAtSeq for contract-test golden values.
package main

import (
	"fmt"

	"github.com/grapeid/sp-witness-watcher/internal/digest"
)

func main() {
	ev := map[string]interface{}{
		"v": "KERI10JSON000256_", "t": "icp", "i": "EAlice", "s": "0",
		"k": []interface{}{"Dkey1"},
	}
	d, err := digest.KelDigestAtSeq([]map[string]interface{}{ev}, 0)
	fmt.Println(d, err)
}