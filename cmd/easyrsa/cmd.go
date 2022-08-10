package main

import (
	"fmt"
	"github.com/kemsta/go-easyrsa/pkg/pki"
	"github.com/spf13/cobra"
	"log"
	"net"
	"os"
)

var keyDir string
var pkiI *pki.PKI
var serverDnsNames []string
var serverIPs []net.IP

var rootCmd = &cobra.Command{
	Use: "easyrsa",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		var err error
		pkiI, err = getPki()
		if err != nil {
			log.Fatal(err)
		}
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
		_, err := pkiI.NewCa()
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
		options := []pki.Option{pki.Server()}
		if serverDnsNames != nil {
			options = append(options, pki.DNSNames(serverDnsNames))
		}
		if serverIPs != nil {
			options = append(options, pki.IPAddresses(serverIPs))
		}
		if _, err := pkiI.NewCert(args[0], options...); err != nil {
			fmt.Println(fmt.Errorf("can`t build server pair: %s", err))
		}
	},
}

var buildKey = &cobra.Command{
	Use:   "build-key [cn]",
	Short: "build client cert/key",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, err := pkiI.NewCert(args[0], pki.Client())
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
		err := pkiI.RevokeAllByCN(args[0])
		if err != nil {
			fmt.Println(fmt.Errorf("can`t revoke cert: %s", err))
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&keyDir, "key-dir", "k", "keys", "")
	buildServerKey.Flags().StringArrayVarP(&serverDnsNames, "dns", "n", nil, "server dns names")
	buildServerKey.Flags().IPSliceVarP(&serverIPs, "ip", "i", nil, "server ip addresses")
	rootCmd.AddCommand(buildCa)
	rootCmd.AddCommand(buildServerKey)
	rootCmd.AddCommand(buildKey)
	rootCmd.AddCommand(revokeFull)
}

func getPki() (*pki.PKI, error) {
	return pki.InitPKI(keyDir, nil)
}
