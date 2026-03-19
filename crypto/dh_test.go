package pkicrypto_test

import (
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkicrypto "github.com/kemsta/go-easyrsa/crypto"
)

func TestGenDHParams_Basic(t *testing.T) {
	pemBytes, err := pkicrypto.GenDHParams(128)
	require.NoError(t, err)
	assert.Contains(t, string(pemBytes), "DH PARAMETERS")
}

func TestGenDHParams_Parseable(t *testing.T) {
	pemBytes, err := pkicrypto.GenDHParams(128)
	require.NoError(t, err)

	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	assert.Equal(t, "DH PARAMETERS", block.Type)

	var params struct {
		P *big.Int
		G *big.Int
	}
	_, err = asn1.Unmarshal(block.Bytes, &params)
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(2), params.G)
	assert.NotNil(t, params.P)
}
