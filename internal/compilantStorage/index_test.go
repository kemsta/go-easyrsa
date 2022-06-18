package compilantStorage

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"strings"
	"testing"
	"time"
)

type fakeReader struct {
}

func (f fakeReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrClosedPipe
}

type fakeWriter struct {
}

func (f fakeWriter) Write(p []byte) (n int, err error) {
	return 0, io.ErrClosedPipe
}

func TestIndex_Decode(t *testing.T) {
	type args struct {
		r io.Reader
	}
	tests := []struct {
		name    string
		i       *Index
		args    args
		wantErr bool
		funcV   func(index *Index, t *testing.T) bool
	}{
		{
			name: "mt",
			i:    new(Index),
			args: args{
				r: strings.NewReader(""),
			},
			wantErr: false,
			funcV: func(index *Index, t *testing.T) bool {
				return true
			},
		},
		{
			name: "oneline",
			i:    new(Index),
			args: args{
				r: strings.NewReader("V\t240830094439Z\t\tA687897D709E441C85A0B2EF9C02C80D\tunknown\t/CN=test1"),
			},
			wantErr: false,
			funcV: func(index *Index, t *testing.T) bool {
				return assert.Equal(t, 1, index.Len())
			},
		},
		{
			name: "multiline",
			i:    new(Index),
			args: args{
				r: strings.NewReader("V\t240830094439Z\t\tA687897D709E441C85A0B2EF9C02C80D\tunknown\t/CN=test1\nR\t240831190001Z\t220529195720Z\tB2B9D80AE52F4E739FB1A4D696417D30\tunknown\t/CN=client\nR\t240831190253Z\t220618182903Z,keyCompromise\tCBF3370F0AB460655DF6FA60FFCA421F\tunknown\t/CN=client2\nV\t240831190819Z\t\tC3B12A550081FB41EF0F67C3678EA4BC\tunknown\t/CN=server\n"),
			},
			wantErr: false,
			funcV: func(index *Index, t *testing.T) bool {
				return assert.Equal(t, 4, index.Len())
			},
		},
		{
			name: "fakereader",
			i:    new(Index),
			args: args{
				r: new(fakeReader),
			},
			wantErr: true,
			funcV: func(index *Index, t *testing.T) bool {
				return true
			},
		},
		{
			name: "brokenrecord",
			i:    new(Index),
			args: args{
				r: strings.NewReader("V\t240830094439Z\t\tA687897D709E441C85A0B2EF9C02C80D\tunknown"),
			},
			wantErr: true,
			funcV: func(index *Index, t *testing.T) bool {
				return true
			},
		},
		{
			name: "wrong exp date",
			i:    new(Index),
			args: args{
				r: strings.NewReader("R\t241331190253Z\t220630182903Z,keyCompromise\tCBF3370F0AB460655DF6FA60FFCA421F\tunknown\t/CN=client2"),
			},
			wantErr: true,
			funcV: func(index *Index, t *testing.T) bool {
				return true
			},
		},
		{
			name: "wrong revoc date",
			i:    new(Index),
			args: args{
				r: strings.NewReader("R\t240831190253Z\t220632182903Z,keyCompromise\tCBF3370F0AB460655DF6FA60FFCA421F\tunknown\t/CN=client2"),
			},
			wantErr: true,
			funcV: func(index *Index, t *testing.T) bool {
				return true
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.i.Decode(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
			} else {
				tt.funcV(tt.i, t)
			}
		})
	}
}

func TestIndex_Encode(t *testing.T) {
	dt := time.Date(2020, 01, 06, 12, 24, 24, 00, time.UTC)
	type fields struct {
		records []Record
	}
	tests := []struct {
		name    string
		fields  fields
		wantW   string
		wantErr assert.ErrorAssertionFunc
		writer  io.Writer
	}{
		{
			name:   "mt",
			fields: fields{},
			wantW:  "",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return true
			},
			writer: nil,
		},
		{
			name: "good",
			fields: fields{
				records: []Record{
					{
						statusFlag:       86,
						expirationDate:   &dt,
						revocationDate:   nil,
						revocationReason: "",
						certSerialHex:    "AB12",
						certFileName:     "unknown",
						certDN:           "/CN=client3",
					},
					{
						statusFlag:       86,
						expirationDate:   &dt,
						revocationDate:   &dt,
						revocationReason: "keyCompromise",
						certSerialHex:    "AB12",
						certFileName:     "unknown",
						certDN:           "/CN=client3",
					},
				},
			},
			wantW: "V\t200106122424Z\t\tAB12\tunknown\t/CN=client3V\t200106122424Z\t200106122424Z,keyCompromise\tAB12\tunknown\t/CN=client3",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.NoError(t, err)
			},
		},
		{
			name: "good",
			fields: fields{
				records: []Record{
					{
						statusFlag:       86,
						expirationDate:   &dt,
						revocationDate:   nil,
						revocationReason: "",
						certSerialHex:    "AB12",
						certFileName:     "unknown",
						certDN:           "/CN=client3",
					},
					{
						statusFlag:       86,
						expirationDate:   &dt,
						revocationDate:   &dt,
						revocationReason: "keyCompromise",
						certSerialHex:    "AB12",
						certFileName:     "unknown",
						certDN:           "/CN=client3",
					},
				},
			},
			wantW: "",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Error(t, err)
			},
			writer: fakeWriter{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			i := &Index{
				records: tt.fields.records,
			}
			w := &bytes.Buffer{}
			if tt.writer != nil {
				err = i.Encode(tt.writer)
			} else {
				err = i.Encode(w)
			}

			if !tt.wantErr(t, err, fmt.Sprintf("Encode(%v)", w)) {
				return
			}
			assert.Equalf(t, tt.wantW, w.String(), "Encode(%v)", w)
		})
	}
}
