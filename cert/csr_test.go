package cert_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certpkg "github.com/kemsta/go-easyrsa/v2/cert"
)

func TestCSR_RequestAndSubject(t *testing.T) {
	pk := newTestPKI(t)

	csrPEM, err := pk.GenReq("client1")
	require.NoError(t, err)

	csr := &certpkg.CSR{Name: "client1", CSRPEM: csrPEM}
	req, err := csr.Request()
	require.NoError(t, err)
	require.NotNil(t, req)
	assert.Equal(t, "client1", req.Subject.CommonName)

	subject, err := csr.Subject()
	require.NoError(t, err)
	assert.Equal(t, req.Subject, subject)
}

func TestCSR_RequestAndSubjectErrors(t *testing.T) {
	csr := &certpkg.CSR{Name: "broken", CSRPEM: []byte("not a csr")}

	_, err := csr.Request()
	assert.Error(t, err)

	subject, err := csr.Subject()
	assert.Error(t, err)
	assert.Empty(t, subject.CommonName)
}
