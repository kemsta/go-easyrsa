package migration

import "github.com/kemsta/go-easyrsa/pki"

// Migrate exports the source PKI metadata and streams its pairs into the target PKI.
func Migrate(source, target *pki.PKI) error {
	snapshot, err := source.ExportSnapshot()
	if err != nil {
		return err
	}
	return target.ImportSnapshot(snapshot, source.ExportPairs)
}
