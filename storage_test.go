package pki

import (
	"bytes"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func getTestDir() string {
	res, _ := filepath.Abs("test_data")
	return res
}

func TestNewDirKeyStorage(t *testing.T) {
	type args struct {
		keydir string
	}
	tests := []struct {
		name    string
		args    args
		want    *DirKeyStorage
		wantErr bool
	}{
		{
			name: "empty",
			args: args{
				keydir: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "not exist",
			args: args{
				keydir: "not exist/dir",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "good",
			args: args{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			want:    &DirKeyStorage{keydir: filepath.Join(getTestDir(), "dir_keystorage")},
			wantErr: false,
		},
		{
			name: "not abs",
			args: args{
				keydir: filepath.Join("test_data", "dir_keystorage"),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDirKeyStorage(tt.args.keydir)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDirKeyStorage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDirKeyStorage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDirKeyStorage_makePath(t *testing.T) {
	type fields struct {
		keydir string
	}
	type args struct {
		pair *X509Pair
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
				pair: &X509Pair{
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
				pair: &X509Pair{
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
				pair: &X509Pair{
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
				pair: &X509Pair{
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
		pair *X509Pair
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
				pair: &X509Pair{
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
				pair: &X509Pair{
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
				pair: &X509Pair{
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
				pair: &X509Pair{
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
			name: "not exist",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				cn: "not_exist",
			},
			wantErr: true,
		},
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

//
//func TestDirKeyStorage_GetByCN(t *testing.T) {
//	want := []*X509Pair{NewX509Pair([]byte("keybytes"), []byte("certbytes"), "good_cert", big.NewInt(66))}
//	t.Run("good storage", func(t *testing.T) {
//		s := &DirKeyStorage{
//			keydir: filepath.Join(getTestDir(), "dir_keystorage"),
//		}
//		got, err := s.GetByCN("good_cert")
//		if err != nil {
//			t.Errorf("DirKeyStorage.GetByCN() error = %v", err)
//			return
//		}
//		if !reflect.DeepEqual(got, want) {
//			t.Errorf("DirKeyStorage.GetByCN() got = %v but want = %v", got, want)
//		}
//	})
//}

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
		want    []*X509Pair
		wantErr bool
	}{
		{
			name: "bad cert",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				cn: "bad_cert",
			},
			want:    make([]*X509Pair, 0),
			wantErr: false,
		},
		{
			name: "bad key",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				cn: "bad_key",
			},
			want:    make([]*X509Pair, 0),
			wantErr: false,
		},
		{
			name: "good cert",
			fields: fields{
				keydir: filepath.Join(getTestDir(), "dir_keystorage"),
			},
			args: args{
				cn: "good_cert",
			},
			want:    []*X509Pair{NewX509Pair([]byte("keybytes"), []byte("certbytes"), "good_cert", big.NewInt(66))},
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
		want    *X509Pair
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
			want:    NewX509Pair([]byte("keybytes"), []byte("certbytes"), "good_cert", big.NewInt(66)),
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
