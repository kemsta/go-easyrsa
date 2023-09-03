package compliantStorage

import (
	"bytes"
	"github.com/kemsta/go-easyrsa/pkg/pair"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func getTestDir() string {
	res, _ := filepath.Abs("test")
	return res
}

func TestDirKeyStorage_Put(t *testing.T) {
	type fields struct {
		keydir string
	}
	type args struct {
		pair *pair.X509Pair
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "good",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				pair: pair.ImportX509([]byte("keybytes"), []byte("certbytes"), "good_cert", big.NewInt(66)),
			},
			wantErr: false,
		},
		{
			name: "ca",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				pair: pair.ImportX509([]byte("keybytes"), []byte("certbytes"), "ca", big.NewInt(154)),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &DirKeyStorage{
				pkidir: tt.fields.keydir,
			}
			if err := s.Put(tt.args.pair); (err != nil) != tt.wantErr {
				t.Errorf("DirKeyStorage.Put() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	certBytes, _ := os.ReadFile(filepath.Join(getTestDir(), "dir_keystorage", "issued/good_cert.crt"))
	if !bytes.Equal(certBytes, []byte("certbytes")) {
		t.Errorf("DirKeyStorage.Put() wrong cert bytes in result file")
	}
	certBytes, _ = os.ReadFile(filepath.Join(getTestDir(), "dir_keystorage", "certs_by_serial/9A.crt"))
	if !bytes.Equal(certBytes, []byte("certbytes")) {
		t.Errorf("DirKeyStorage.Put() wrong cert bytes in result file")
	}
	certBytes, _ = os.ReadFile(filepath.Join(getTestDir(), "dir_keystorage", "ca.crt"))
	if !bytes.Equal(certBytes, []byte("certbytes")) {
		t.Errorf("DirKeyStorage.Put() wrong cert bytes in result file")
	}
	keyBytes, _ := os.ReadFile(filepath.Join(getTestDir(), "dir_keystorage", "private/good_cert.key"))
	if !bytes.Equal(keyBytes, []byte("keybytes")) {
		t.Errorf("DirKeyStorage.Put() wrong key bytes in result file")
	}
}
