package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/pki"
)

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), err
}

func openFS(t *testing.T, dir string, cfg pki.Config) *pki.PKI {
	t.Helper()
	pk, err := pki.NewWithFS(dir, cfg)
	require.NoError(t, err)
	return pk
}

func parseDHParameterBits(t *testing.T, pemBytes []byte) int {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Equal(t, "DH PARAMETERS", block.Type)
	var params struct {
		P *big.Int
		G *big.Int
	}
	_, err := asn1.Unmarshal(block.Bytes, &params)
	require.NoError(t, err)
	require.NotNil(t, params.P)
	return params.P.BitLen()
}
