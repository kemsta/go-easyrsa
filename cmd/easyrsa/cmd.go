package main

import (
	"crypto/x509/pkix"
	"fmt"
	"github.com/kemsta/go-easyrsa"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

var keyDir string
var pki *easyrsa.PKI

var rootCmd = &cobra.Command{
	Use: "easyrsa",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initPki()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var buildCa = &cobra.Command{
	Use:   "build-ca",
	Short: "build ca cert/key",
	Run: func(cmd *cobra.Command, args []string) {
		_, err := pki.NewCa()
		if err != nil {
			fmt.Println(fmt.Errorf("can`t build ca pair: %s", err))
		}
	},
}

var buildServerKey = &cobra.Command{
	Use:   "build-server-key [cn]",
	Short: "build server cert/key",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, err := pki.NewCert(args[0], true)
		if err != nil {
			fmt.Println(fmt.Errorf("can`t build server pair: %s", err))
		}
	},
}

var buildKey = &cobra.Command{
	Use:   "build-key [cn]",
	Short: "build client cert/key",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, err := pki.NewCert(args[0], false)
		if err != nil {
			fmt.Println(fmt.Errorf("can`t build client pair: %s", err))
		}
	},
}

var revokeFull = &cobra.Command{
	Use:   "revoke-full [cn]",
	Short: "revoke cert",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := pki.RevokeAllByCN(args[0])
		if err != nil {
			fmt.Println(fmt.Errorf("can`t revoke cert: %s", err))
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&keyDir, "key-dir", "k", "keys", "")
	rootCmd.AddCommand(buildCa)
	rootCmd.AddCommand(buildServerKey)
	rootCmd.AddCommand(buildKey)
	rootCmd.AddCommand(revokeFull)
}

func initPki() {
	err := os.MkdirAll(keyDir, 0750)
	if err != nil {
		fmt.Println(fmt.Errorf("can`t create key dir: %s", err))
	}
	storage := easyrsa.NewDirKeyStorage(keyDir)
	serialProvider := easyrsa.NewFileSerialProvider(filepath.Join(keyDir, "index.txt"))
	crlHolder := easyrsa.NewFileCRLHolder(filepath.Join(keyDir, "crl.pem"))
	pki = easyrsa.NewPKI(storage, serialProvider, crlHolder, pkix.Name{})
}
