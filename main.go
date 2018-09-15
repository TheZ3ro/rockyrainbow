package main

import (
	"fmt"
	"log"
	"os"

	"./rockyrainbow"
)

var h = map[string]rockyrainbow.Hash{
	"md5":    rockyrainbow.MD5,
	"sha256": rockyrainbow.SHA256,
	"sha512": rockyrainbow.SHA512,
}

func usage() {
	fmt.Printf("Usage: %s <inputfile> <hash_algorithm>\n", os.Args[0])
	fmt.Println("Supported hashes:")
	for a := range h {
		fmt.Printf("%s ", a)
	}
	fmt.Println()
}

func main() {

	argsLen := len(os.Args)

	if argsLen < 2 {
		usage()
		return
	}
	fileName := func(f string) string {
		if _, err := os.Stat(f); err != nil {
			log.Fatal(err)
		}
		return f
	}(os.Args[1])

	hashAlgo := func() rockyrainbow.Hash {
		if argsLen < 3 {
			return rockyrainbow.MD5
		}
		return h[os.Args[2]]
	}()

	r := new(rockyrainbow.RockyRainbow)
	r.InputFile = fileName
	r.HashAlgorithm = hashAlgo
	rocky, err := rockyrainbow.New(r)
	if err != nil {
		log.Fatal(err)
	}

	rocky.Start()
}