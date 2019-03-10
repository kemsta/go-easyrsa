package easyrsa

import (
	"reflect"
	"testing"
)

func TestNewNotExist(t *testing.T) {
	type args struct {
		err string
	}
	tests := []struct {
		name string
		args args
		want *NotExist
	}{
		{
			name: "just create",
			args: args{
				err: "msg",
			},
			want: &NotExist{"msg"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewNotExist(tt.args.err); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewNotExist() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNotExist_Error(t *testing.T) {
	type fields struct {
		err string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "msg",
			fields: fields{
				err: "msg",
			},
			want: "msg",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &NotExist{
				err: tt.fields.err,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("NotExist.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}
