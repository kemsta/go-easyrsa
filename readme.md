# EasyRsa
[![Build Status](https://travis-ci.org/kemsta/go-easyrsa.svg?branch=master)](https://travis-ci.org/kemsta/go-easyrsa)
[![Coverage Status](https://coveralls.io/repos/github/kemsta/go-easyrsa/badge.svg?branch=master)](https://coveralls.io/github/kemsta/go-easyrsa?branch=master)
[![GoDoc](https://godoc.org/github.com/kemsta/go-easyrsa?status.svg)](https://godoc.org/github.com/kemsta/go-easyrsa)

Simple golang implementation some [easy-rsa](https://github.com/OpenVPN/easy-rsa) functions

## cli usage examples

go get github.com/kemsta/go-easyrsa/easyrsa-cli

### build ca pair
easyrsa-cli -k keys build-ca

### build server pair
easyrsa-cli -k keys build-server-key some-server-name

### build client pair
easyrsa-cli -k keys build-key some-client-name

### revoke cert
easyrsa-cli -k keys revoke-full some-client-name
