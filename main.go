package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/rimantoro/mytools/chiper"
)

func main() {

	var err error

	usagePrefix := `
Usage for generate signature: 
	app generate /go/to/privkey/path payload

Usage for validate signature: 
	app validate /go/to/pubkey/path payload signature
	`

	if len(os.Args) < 3 {
		log.Print(usagePrefix)
		os.Exit(1)
	}

	strMode := os.Args[1]    // "generate" "validate"
	strKey := os.Args[2]     // privkey for mode=generate, pubkey for mode=validate
	strPayload := os.Args[3] // string payload to generate from or validate

	switch strMode {
	case "generate":
		sign, err := chiper.GenerateResponseSignature(strPayload, strKey)
		if err != nil {
			log.Fatalf("SIGNATURE : %s \n", err.Error())
			os.Exit(1)
		}
		fmt.Printf("[GENERATE] PAYLOAD=%s \n SIGN=%s \n", strPayload, sign)
		os.Exit(0)
	case "validate":
		if len(os.Args) < 4 {
			log.Print(usagePrefix)
			os.Exit(1)
		}

		strSign := os.Args[4] // string signature
		bPrivKey, err := ioutil.ReadFile(strKey)
		if err != nil {
			fmt.Printf("INALID PUBKEY PATH : %s \n", err.Error())
			os.Exit(1)
		}

		log.Printf("DEBUG BOR - BYTE PRIVKEY = %v", string(bPrivKey))

		err = chiper.VerifySignature(strSign, bPrivKey, strPayload)
		if err != nil {
			fmt.Printf("INVALID SIGNATURE : %s \n", err.Error())
			os.Exit(1)
		}
	}

	flag.Parse()

	fmt.Printf("%s\n", err.Error())
	os.Exit(1)
}
