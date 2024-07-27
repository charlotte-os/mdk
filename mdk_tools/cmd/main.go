package main

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	mdktools "github.com/charlotte-os/charlotte-core/mdk_tools"
	"github.com/fxamacker/cbor/v2"
	"log"
	"math"
	"os"
)

var InFile = flag.String("in", "", "input file (required)")
var Cert = flag.String("cert", "", "certificate file (required)")

//func askPass(prompt string) ([]byte, error) {
//	fmt.Printf("%s: ", prompt)
//	bytePassword, err := term.ReadPassword(syscall.Stdin)
//	if err != nil {
//		return nil, err
//	}
//	fmt.Println()
//	return bytePassword, nil
//}

func fileExistsAndIsFile(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func statAndOpenFile(filename string) (*os.File, os.FileInfo, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	return f, info, nil
}

func main() {
	flag.Parse()

	if *InFile == "" {
		fmt.Println("Please specify -in file")
		return
	} else if *Cert == "" {
		fmt.Println("Please specify -cert file")
		return
	}

	if !fileExistsAndIsFile(*InFile) || !fileExistsAndIsFile(*Cert) {
		return
	}

	pemBytes, err := os.ReadFile(*Cert)
	if err != nil {
		log.Panicf("Error reading certificate file: %s", err)
	}

	var sigHandler *mdktools.CodeSig

	for {
		var pkpass []byte
		pkpass = []byte(os.Getenv("CERT_PASS"))
		s, err := mdktools.NewSigner(pemBytes, pkpass, crypto.SHA256)
		if err != nil {
			var mdkerr *mdktools.MdkError
			if errors.As(err, &mdkerr) {
				continue
			}
			log.Panicf("Error creating signer: %s", err)
		}
		sigHandler = s
		break
	}

	f, info, err := statAndOpenFile(*InFile)
	if err != nil {
		log.Panicf("Error opening input file: %s", err)
	}
	defer f.Close()

	sig, err := sigHandler.Sign(f, info.Size())
	if err != nil {
		log.Panicf("Error signing input file: %s", err)
	}

	fmt.Printf("Signature info:\n%s", sig)

	err = addSignatureToBinary(sig, *InFile)
	if err != nil {
		panic(err)
	}
}

func addSignatureToBinary(sig *mdktools.SignatureEnvelope, input string) error {
	sigBytes, err := cbor.Marshal(sig)
	if err != nil {
		return err
	}

	data := make([]byte, len(sigBytes)+6)
	buf := bytes.NewBuffer(data)
	buf.Reset()
	buf.Write([]byte("DSIG"))
	if len(sigBytes) >= math.MaxUint16 {
		return errors.New("signature size exceeds maximum size")
	}
	binary.Write(buf, binary.BigEndian, uint16(len(sigBytes)))
	buf.Write(sigBytes)

	f, err := os.OpenFile(input, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	// expand file to make sure there's enough space to write the signature in
	fend, err := f.Seek(0, 2)
	if err != nil {
		return err
	}

	for range len(sigBytes) {
		f.Write([]byte{0xFF})
	}

	f.Seek(fend, 0)

	_, err = buf.WriteTo(f)

	return err
}
