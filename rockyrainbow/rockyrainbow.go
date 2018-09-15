package rockyrainbow

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Hash is the hash type for rockyrainbow
type Hash int

const (
	MD5 Hash = iota
	SHA256
	SHA512
)

// from Hash constants
var hashNames = []string{
	"md5",
	"sha256",
	"sha512",
}

const defaultWorkersCount = 256

// RockyRainbow main config struct
type RockyRainbow struct {
	InputFile     string
	OutputFile    string
	HashAlgorithm Hash
	WorkersCount  int

	inFile  *os.File
	outFile *os.File
	m       sync.Mutex

	done chan bool
	msgs chan string
}

// New creates a new RockyRainbow instance
func New(r *RockyRainbow) (*RockyRainbow, error) {
	runtime.GOMAXPROCS(16)
	if r.InputFile == "" {
		return nil, errors.New("InputFile is mandatory")
	}
	if int(r.HashAlgorithm) > len(hashNames) {
		return nil, errors.New("Unsupported algorithm")
	}
	if r.OutputFile == "" {
		r.OutputFile = r.createOutputFileName()
	}
	if r.WorkersCount == 0 {
		r.WorkersCount = defaultWorkersCount
	}
	r.done = make(chan bool)
	r.msgs = make(chan string)

	return r, nil
}

// Start the rockyrainbow process
func (r *RockyRainbow) Start() (err error) {
	r.outFile, err = os.Create(r.OutputFile)
	if err != nil {
		return
	}
	r.inFile, err = os.Open(r.InputFile)
	if err != nil {
		return
	}
	defer func() {
		r.inFile.Close()
		r.outFile.Close()
	}()

	log.Printf("Loading %d workers", r.WorkersCount)
	for i := 0; i < r.WorkersCount; i++ {
		go r.worker()
	}
	log.Println("Waiting for workers to complete...")
	for i := 0; i < r.WorkersCount; i++ {
		<-r.done
	}
	time.Sleep(1 * time.Second)
	return
}
func (r *RockyRainbow) queuer() {
	scanner := bufio.NewScanner(r.inFile)
	for scanner.Scan() {
		r.msgs <- scanner.Text()
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	close(r.msgs)
}

func (r *RockyRainbow) worker() {
	for msg := range r.msgs {
		var h hash.Hash
		switch r.HashAlgorithm {
		case MD5:
			h = md5.New()
			break
		case SHA256:
			h = sha256.New()
			break
		case SHA512:
			h = sha512.New()
			break
		}
		h.Write([]byte(msg))
		r.m.Lock()
		r.outFile.WriteString(
			fmt.Sprintf(
				"%s:%s\n",
				msg,
				hex.EncodeToString(h.Sum(nil)),
			),
		)
		r.m.Unlock()
	}
	r.done <- true
}

func (r *RockyRainbow) createOutputFileName() string {
	lastDotPos := strings.LastIndex(r.InputFile, ".")
	if lastDotPos == -1 {
		lastDotPos = len(r.InputFile)
	}
	return r.InputFile[0:lastDotPos] + "_precomputed_" + hashNames[r.HashAlgorithm] + ".txt"
}
