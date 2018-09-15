package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

var done = make(chan bool)
var msgs = make(chan string)

var algorithms = []string{
	"md5",
	"sha256",
	"sha512",
}

var workersCount = 256

func rainbowProduce(inputFile string) {
	file, err := os.Open(inputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		msgs <- scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	close(msgs)
}

func rainbowConsume(outputFile *os.File, alg string) {
	for msg := range msgs {
		var h hash.Hash
		switch alg {
		case "md5":
			h = md5.New()
			break
		case "sha256":
			h = sha256.New()
			break
		case "sha512":
			h = sha512.New()
			break
		}
		_, err := io.WriteString(h, msg)
		outputFile.WriteString(
			fmt.Sprintf(
				"%s:%s\n",
				msg,
				hex.EncodeToString(h.Sum(nil)),
			),
		)
		if err != nil {
			log.Fatal(err)
		}
	}
	done <- true
}

func createOutputFileName(inputFile string, alg string) string {
	lastDotPos := strings.LastIndex(inputFile, ".")
	if lastDotPos == -1 {
		lastDotPos = len(alg)
	}
	return inputFile[0:lastDotPos] + "_precomputed_" + alg + ".txt"
}

func isSupportedAlgorithm(alg string) bool {
	for _, a := range algorithms {
		if alg == a {
			return true
		}
	}
	return false
}
func usage() {
	fmt.Printf("Usage: %s <inputfile> <hash_algorithm>\n", os.Args[0])
	fmt.Println("Supported hashes:")
	for _, a := range algorithms {
		fmt.Printf("%s ", a)
	}
	fmt.Println()
}

func main() {
	runtime.GOMAXPROCS(16)

	argsLen := len(os.Args)

	if argsLen < 2 {
		usage()
		return
	}

	go rainbowProduce(os.Args[1])

	algName := "md5"
	if argsLen == 3 {
		if isSupportedAlgorithm(os.Args[2]) {
			algName = os.Args[2]
		}
	}

	outputFileName := createOutputFileName(os.Args[1], algName)
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer outputFile.Close()

	log.Printf("Loading %d workers", workersCount)
	for i := 0; i < workersCount; i++ {
		go rainbowConsume(outputFile, algName)
	}
	log.Println("Waiting for workers to complete...")
	for i := 0; i < workersCount; i++ {
		<-done
	}
	time.Sleep(1 * time.Second)
}
