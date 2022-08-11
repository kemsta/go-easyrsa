# EasyRsa
[![Build Status](https://github.com/kemsta/go-easyrsa/actions/workflows/test.yml/badge.svg)](https://github.com/kemsta/go-easyrsa/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/kemsta/go-easyrsa/badge.svg?branch=master)](https://coveralls.io/github/kemsta/go-easyrsa?branch=master)
[![GoDoc](https://godoc.org/github.com/kemsta/go-easyrsa?status.svg)](https://godoc.org/github.com/kemsta/go-easyrsa)

Simple golang implementation some [easy-rsa](https://github.com/OpenVPN/easy-rsa) functions

## cli usage examples

go install github.com/kemsta/go-easyrsa/cmd/easyrsa@latest

### build ca pair
easyrsa -k keys build-ca

### build server pair
easyrsa -k keys build-server-key some-server-name

### build client pair
easyrsa -k keys build-key some-client-name

### revoke cert
easyrsa -k keys revoke-full some-client-name
