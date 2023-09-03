package compliantStorage

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const dateLayout = "060102150405Z"

type Index struct {
	records []Record
}

//https://pki-tutorial.readthedocs.io/en/latest/cadb.html
//https://www.openssl.org/docs/man1.0.2/man1/openssl-ca.html

type Record struct {
	statusFlag       rune       //Certificate status flag (V=valid, R=revoked, E=expired)
	expirationDate   *time.Time //Certificate expiration date
	revocationDate   *time.Time //Certificate revocation date, empty if not revoked
	revocationReason string     //Certificate revocation reason if presented
	certSerialHex    string     //Certificate serial number in hex
	certFileName     string     //Certificate filename or literal string ‘unknown’
	certDN           string     //Certificate distinguished name
}

func (r Record) String() string {
	var revString string
	if r.revocationDate != nil {
		revString = r.revocationDate.Format(dateLayout)
		if r.revocationReason != "" {
			revString = fmt.Sprintf("%v,%v", r.revocationDate.Format(dateLayout), r.revocationReason)
		}
	}

	return fmt.Sprintf("%v\t%v\t%v\t%v\t%v\t%v", string(r.statusFlag), r.expirationDate.Format(dateLayout), revString,
		r.certSerialHex, r.certFileName, r.certDN)
}

func (i *Index) Len() int {
	return len(i.records)
}

func (i *Index) Decode(r io.Reader) error {
	br := bufio.NewReader(r)
	for {
		line, _, err := br.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("couldn't read line from index: %w", err)
		}

		record, err := parseLine(line)
		if err != nil {
			return fmt.Errorf("couldn't parse record %s from index: %w", line, err)
		}
		i.records = append(i.records, *record)
	}
	return nil
}

func parseLine(line []byte) (*Record, error) {
	split := strings.Split(string(line), "\t")
	if len(split) != 6 {
		return nil, fmt.Errorf("wrong records format: %v", string(line))
	}
	rec := new(Record)
	rec.statusFlag, _ = utf8.DecodeRuneInString(split[0])
	parsedDate, err := time.Parse(dateLayout, split[1])
	if err != nil {
		return nil, fmt.Errorf("couldn't parse date from %v : %w", split[1], err)
	}
	rec.expirationDate = &parsedDate
	if split[2] != "" {
		revoc := strings.Split(split[2], ",")
		parsedDate, err = time.Parse(dateLayout, revoc[0])
		if err != nil {
			return nil, fmt.Errorf("couldn't parse date from %v : %w", split[2], err)
		}
		rec.revocationDate = &parsedDate
		if len(revoc) == 2 {
			rec.revocationReason = revoc[1]
		}
	}

	rec.certSerialHex = split[3]
	rec.certFileName = split[4]
	rec.certDN = split[5]

	return rec, nil
}

func (i *Index) Encode(w io.Writer) error {
	for _, r := range i.records {
		_, err := w.Write([]byte(r.String()))
		if err != nil {
			return fmt.Errorf("couldn't write encoded index: %w", err)
		}
	}
	return nil
}
