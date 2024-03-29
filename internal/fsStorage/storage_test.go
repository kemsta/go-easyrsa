package fsStorage

import (
	"bytes"
	"crypto/x509/pkix"
	"fmt"
	"github.com/kemsta/go-easyrsa/pkg/pair"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getTestDir() string {
	res, _ := filepath.Abs("test")
	return res
}

func TestDirKeyStorage_makePath(t *testing.T) {
	type fields struct {
		keydir string
	}
	type args struct {
		pair *pair.X509Pair
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		wantCertPath string
		wantKeyPath  string
		wantErr      bool
	}{
		{
			name: "empty cn",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				pair: &pair.X509Pair{
					KeyPemBytes:  nil,
					CertPemBytes: nil,
					CN:           "",
					Serial:       big.NewInt(66),
				},
			},
			wantCertPath: "",
			wantKeyPath:  "",
			wantErr:      true,
		},
		{
			name: "empty serial",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				pair: &pair.X509Pair{
					KeyPemBytes:  nil,
					CertPemBytes: nil,
					CN:           "good_cert",
					Serial:       nil,
				},
			},
			wantCertPath: "",
			wantKeyPath:  "",
			wantErr:      true,
		},
		{
			name: "can`t create dir",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				pair: &pair.X509Pair{
					KeyPemBytes:  nil,
					CertPemBytes: nil,
					CN:           "bad_path",
					Serial:       big.NewInt(66),
				},
			},
			wantCertPath: "",
			wantKeyPath:  "",
			wantErr:      true,
		},
		{
			name: "good",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				pair: &pair.X509Pair{
					KeyPemBytes:  nil,
					CertPemBytes: nil,
					CN:           "good_cert",
					Serial:       big.NewInt(66),
				},
			},
			wantCertPath: filepath.Join(getTestDir(), "dir_keystorage", "good_cert/42.crt"),
			wantKeyPath:  filepath.Join(getTestDir(), "dir_keystorage", "good_cert/42.key"),
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &DirKeyStorage{
				keydir: tt.fields.keydir,
			}
			gotCertPath, gotKeyPath, err := s.makePath(tt.args.pair)
			if (err != nil) != tt.wantErr {
				t.Errorf("DirKeyStorage.makePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotCertPath != tt.wantCertPath {
				t.Errorf("DirKeyStorage.makePath() gotCertPath = %v, want %v", gotCertPath, tt.wantCertPath)
			}
			if gotKeyPath != tt.wantKeyPath {
				t.Errorf("DirKeyStorage.makePath() gotKeyPath = %v, want %v", gotKeyPath, tt.wantKeyPath)
			}
		})
	}
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
			name: "can`t make path",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				pair: &pair.X509Pair{
					KeyPemBytes:  nil,
					CertPemBytes: nil,
					CN:           "bad_path",
					Serial:       big.NewInt(66),
				},
			},
			wantErr: true,
		},
		{
			name: "good",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				pair: &pair.X509Pair{
					KeyPemBytes:  []byte("keybytes"),
					CertPemBytes: []byte("certbytes"),
					CN:           "good_cert",
					Serial:       big.NewInt(66),
				},
			},
			wantErr: false,
		},
		{
			name: "bad_cert",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				pair: &pair.X509Pair{
					KeyPemBytes:  nil,
					CertPemBytes: nil,
					CN:           "bad_cert",
					Serial:       big.NewInt(66),
				},
			},
			wantErr: true,
		},
		{
			name: "bad_key",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				pair: &pair.X509Pair{
					KeyPemBytes:  nil,
					CertPemBytes: nil,
					CN:           "bad_key",
					Serial:       big.NewInt(66),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &DirKeyStorage{
				keydir: tt.fields.keydir,
			}
			if err := s.Put(tt.args.pair); (err != nil) != tt.wantErr {
				t.Errorf("DirKeyStorage.Put() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	certBytes, _ := ioutil.ReadFile(filepath.Join(getTestDir(), "dir_keystorage", "good_cert/42.crt"))
	if !bytes.Equal(certBytes, []byte("certbytes")) {
		t.Errorf("DirKeyStorage.Put() wrong cert bytes in result file")
	}
	keyBytes, _ := ioutil.ReadFile(filepath.Join(getTestDir(), "dir_keystorage", "good_cert/42.key"))
	if !bytes.Equal(keyBytes, []byte("keybytes")) {
		t.Errorf("DirKeyStorage.Put() wrong key bytes in result file")
	}
}

func TestDirKeyStorage_DeleteByCn(t *testing.T) {
	_ = os.MkdirAll(filepath.Join(getTestDir(), "dir_keystorage", "for_delete"), 0755)
	type fields struct {
		keydir string
	}
	type args struct {
		cn string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "recurse delete",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				cn: "for_delete",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &DirKeyStorage{
				keydir: tt.fields.keydir,
			}
			if err := s.DeleteByCn(tt.args.cn); (err != nil) != tt.wantErr {
				t.Errorf("DirKeyStorage.DeleteByCn() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDirKeyStorage_GetByCN(t *testing.T) {
	type fields struct {
		keydir string
	}
	type args struct {
		cn string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*pair.X509Pair
		wantErr bool
	}{
		{
			name: "not exist",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				cn: "not_exist",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "bad cert",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				cn: "bad_cert",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "bad key",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				cn: "bad_key",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "good cert",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				cn: "good_cert",
			},
			want:    []*pair.X509Pair{pair.NewX509Pair([]byte("keybytes"), []byte("certbytes"), "good_cert", big.NewInt(66))},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &DirKeyStorage{
				keydir: tt.fields.keydir,
			}
			got, err := s.GetByCN(tt.args.cn)
			if (err != nil) != tt.wantErr {
				t.Errorf("DirKeyStorage.GetByCN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DirKeyStorage.GetByCN() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDirKeyStorage_GetBySerial(t *testing.T) {
	type fields struct {
		keydir string
	}
	type args struct {
		serial *big.Int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *pair.X509Pair
		wantErr bool
	}{
		{
			name: "42",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				serial: big.NewInt(66),
			},
			want:    pair.NewX509Pair([]byte("keybytes"), []byte("certbytes"), "good_cert", big.NewInt(66)),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &DirKeyStorage{
				keydir: tt.fields.keydir,
			}
			got, err := s.GetBySerial(tt.args.serial)
			if (err != nil) != tt.wantErr {
				t.Errorf("DirKeyStorage.GetBySerial() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DirKeyStorage.GetBySerial() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDirKeyStorage_DeleteBySerial(t *testing.T) {

	_ = os.MkdirAll(filepath.Join(getTestDir(), "dir_keystorage", "for_delete"), 0755)
	_ = ioutil.WriteFile(filepath.Join(getTestDir(), "dir_keystorage", "for_delete", "a.crt"), []byte(""), 0600)
	_ = ioutil.WriteFile(filepath.Join(getTestDir(), "dir_keystorage", "for_delete", "a.key"), []byte(""), 0600)

	type fields struct {
		keydir string
	}
	type args struct {
		serial *big.Int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "not exist",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				serial: big.NewInt(67),
			},
			wantErr: true,
		},
		{
			name: "exist",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				serial: big.NewInt(10),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &DirKeyStorage{
				keydir: tt.fields.keydir,
			}
			if err := s.DeleteBySerial(tt.args.serial); (err != nil) != tt.wantErr {
				t.Errorf("DirKeyStorage.DeleteBySerial() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFileSerialProvider_Next(t *testing.T) {
	defer func() {
		_ = os.RemoveAll(filepath.Join(getTestDir(), "dir_keystorage", "new_serial"))
		_ = ioutil.WriteFile(filepath.Join(getTestDir(), "dir_keystorage", "wrong_serial"), []byte("gggg"), 0666)
	}()
	type fields struct {
		path string
	}
	tests := []struct {
		name    string
		fields  fields
		want    *big.Int
		wantErr bool
	}{
		{
			name: "not exist dir",
			fields: fields{
				path: filepath.Join(getTestDir(), "dir_keystorage", "not_exist/serial"),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "not exist file",
			fields: fields{
				path: filepath.Join(getTestDir(), "dir_keystorage", "new_serial"),
			},
			want:    big.NewInt(1),
			wantErr: false,
		},
		{
			name: "broken file",
			fields: fields{
				path: filepath.Join(getTestDir(), "dir_keystorage", "wrong_serial"),
			},
			want:    big.NewInt(1),
			wantErr: false,
		},
		{
			name: "dir",
			fields: fields{
				path: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewFileSerialProvider(tt.fields.path)
			got, err := p.Next()
			if (err != nil) != tt.wantErr {
				t.Errorf("FileSerialProvider.Next() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FileSerialProvider.Next() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileCRLHolder_Put(t *testing.T) {
	t.Run("not exist", func(t *testing.T) {
		fileName := filepath.Join(getTestDir(), "dir_keystorage", "not_exist_crl.pem")
		content := []byte("content")
		defer func() {
			_ = os.RemoveAll(fileName)
		}()
		h := NewFileCRLHolder(fileName)
		err := h.Put(content)
		if err != nil {
			t.Errorf("FileCRLHolder.Put() error = %v", err)
		}
		got, _ := ioutil.ReadFile(fileName)
		if !bytes.Equal(got, content) {
			t.Errorf("FileCRLHolder.Put() got = %v, want %v", got, content)
		}
	})
	t.Run("exist", func(t *testing.T) {
		fileName := filepath.Join(getTestDir(), "dir_keystorage", "exist.pem")
		content := []byte("content")
		defer func() {
			_ = ioutil.WriteFile(fileName, []byte("asd"), 0644)
		}()
		h := NewFileCRLHolder(fileName)
		err := h.Put(content)
		if err != nil {
			t.Errorf("FileCRLHolder.Put() error = %v", err)
		}
		got, _ := ioutil.ReadFile(fileName)
		if !bytes.Equal(got, content) {
			t.Errorf("FileCRLHolder.Put() got = %v, want %v", got, content)
		}
	})
	t.Run("dir", func(t *testing.T) {
		fileName := filepath.Join(getTestDir(), "dir_keystorage", "crl.dir")
		content := []byte("content")
		defer func() {
			_ = ioutil.WriteFile(fileName, []byte("asd"), 0666)
		}()
		h := NewFileCRLHolder(fileName)
		err := h.Put(content)
		if err == nil {
			t.Errorf("FileCRLHolder.Put() error = %v", err)
		}
	})
}

func TestFileCRLHolder_Get(t *testing.T) {
	type fields struct {
		path string
	}
	tests := []struct {
		name    string
		fields  fields
		want    *pkix.CertificateList
		wantErr bool
	}{
		{
			name: "not exist",
			fields: fields{
				path: filepath.Join(getTestDir(), "dir_keystorage", "not_exist"),
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "broken",
			fields: fields{
				path: filepath.Join(getTestDir(), "dir_keystorage", "exist.pem"),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "good",
			fields: fields{
				path: filepath.Join(getTestDir(), "dir_keystorage", "good_crl.pem"),
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewFileCRLHolder(tt.fields.path)
			_, err := h.Get()
			if (err != nil) != tt.wantErr {
				t.Errorf("FileCRLHolder.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestDirKeyStorage_GetAll(t *testing.T) {
	storPath := filepath.Join(getTestDir(), "empty_stor")
	stor := NewDirKeyStorage(storPath)
	_ = os.MkdirAll(storPath, 0755)
	defer func() {
		_ = os.RemoveAll(storPath)
	}()
	t.Run("empty stor", func(t *testing.T) {
		all, err := stor.GetAll()
		assert.NoError(t, err)
		assert.NotNil(t, all)
		assert.Empty(t, all)
	})
	t.Run("good stor", func(t *testing.T) {
		_ = stor.Put(pair.NewX509Pair([]byte("keybytes"), []byte("certbytes"), "good_cert", big.NewInt(66)))
		_ = stor.Put(pair.NewX509Pair([]byte("keybytes"), []byte("certbytes"), "good_cert", big.NewInt(65)))
		_ = stor.Put(pair.NewX509Pair([]byte("keybytes"), []byte("certbytes"), "another_cert", big.NewInt(64)))
		all, err := stor.GetAll()
		assert.NoError(t, err)
		assert.NotNil(t, all)
		assert.NotEmpty(t, all)
		assert.Len(t, all, 3)
	})
}

func TestDirKeyStorage_GetLastByCn(t *testing.T) {
	storPath := filepath.Join(getTestDir(), "empty_stor")
	stor := NewDirKeyStorage(storPath)
	_ = os.MkdirAll(filepath.Join(storPath, "any"), 0755)
	defer func() {
		_ = os.RemoveAll(storPath)
	}()
	t.Run("empty stor", func(t *testing.T) {
		all, err := stor.GetLastByCn("any")
		assert.Error(t, err)
		assert.Nil(t, all)
	})
}

func Test_writeFileAtomic(t *testing.T) {
	path := filepath.Join(getTestDir(), "dir_keystorage")
	type args struct {
		path string
		r    io.Reader
		mode os.FileMode
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "not_exist",
			args: args{
				path: filepath.Join(path, "bad_key/not_exist"),
				r:    strings.NewReader("test"),
				mode: 0644,
			},
			wantErr: assert.NoError,
		},
		{
			name: "exist",
			args: args{
				path: filepath.Join(path, "bad_key/42.crt"),
				r:    strings.NewReader("test"),
				mode: 0644,
			},
			wantErr: assert.NoError,
		},
		{
			name: "dir",
			args: args{
				path: filepath.Join(path, "bad_key/42.key"),
				r:    strings.NewReader("test"),
				mode: 0644,
			},
			wantErr: assert.Error,
		},
	}
	defer func(name string) {
		_ = os.Remove(name)
	}(filepath.Join(path, "bad_key/not_exist"))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, writeFileAtomic(tt.args.path, tt.args.r, tt.args.mode), fmt.Sprintf("writeFileAtomic(%v, %v, %v)", tt.args.path, tt.args.r, tt.args.mode))
		})
	}
}
