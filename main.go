package main

import (
	"fmt"
	"log"
	"os"

	"./rockyrainbow"
)

var h = map[string]rockyrainbow.Hash{
	"md5":    rockyrainbow.MD5,
	"sha1":   rockyrainbow.SHA1,
	"sha256": rockyrainbow.SHA256,
	"sha512": rockyrainbow.SHA512,
	"ntlm":   rockyrainbow.NTLM,
}

func usage() bool {
	fmt.Printf("Usage: %s <inputfile> <hash_algorithm>\n", os.Args[0])
	fmt.Println("Supported hashes:")
	for a := range h {
		fmt.Printf("%s ", a)
	}
	fmt.Println()
	return true
}

func main() {

	argsLen := len(os.Args)

	if argsLen < 2 && usage() {
		return
	}

	fileName := func() string {
		f := os.Args[1]
		if _, err := os.Stat(f); err != nil {
			log.Fatal(err)
		}
		return f
	}

	hashAlgo := func() rockyrainbow.Hash {
		if argsLen < 3 {
			return rockyrainbow.MD5
		}
		return h[os.Args[2]]
	}

	r := new(rockyrainbow.RockyRainbow)
	r.InputFile = fileName()
	r.HashAlgorithm = hashAlgo()
	// r.DecoratorFunction = addSalt
	rocky, err := rockyrainbow.New(r)
	if err != nil {
		log.Fatal(err)
	}

	if err = rocky.Start(); err != nil {
		log.Fatal(err)
	}
}

// func addSalt(in []byte) []byte {
// 	salt := []byte{'a', '1', '3', 'f'}
// 	h := md5.New()
// 	h.Write(in)
// 	in = h.Sum(nil)
// 	h.Reset()
// 	h.Write(salt)
// 	return h.Sum(nil)
// }
