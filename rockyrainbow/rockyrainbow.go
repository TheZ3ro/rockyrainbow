package rockyrainbow

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"../go-ntlm"
)

// DecoratorFunction is used for each message before it's hashed. It can be used
// to precompute a list with a salt, for instance.
type DecoratorFunction func([]byte) []byte

// Hash is the hash type for rockyrainbow
type Hash uint

const (
	MD5 Hash = iota
	SHA1
	SHA256
	SHA512
	NTLM
)

// from Hash constants
var hashNames = []string{
	"md5",
	"sha1",
	"sha256",
	"sha512",
	"ntlm",
}

var i = 0

const defaultWorkersCount = 256

// RockyRainbow main config struct
type RockyRainbow struct {
	InputFile         string
	OutputFile        string
	HashAlgorithm     Hash
	WorkersCount      int
	DecoratorFunction DecoratorFunction

	inFile  *os.File
	outFile *os.File
	m       sync.Mutex
	status  bool

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

func lineCounter(filename string) (int, error) {
	r, _ := os.Open(filename)
	defer r.Close()
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := r.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count, nil

		case err != nil:
			return count, err
		}
	}
}

func (r *RockyRainbow) displayConf() {
	bp := func(format string, a ...interface{}) {
		const bullet = "▶"
		fmt.Print(bullet + " ")
		fmt.Printf(format+"\n", a...)
	}
	bp("Input file\t\t%s", r.InputFile)
	bp("Output file\t\t%s", r.OutputFile)
	bp("Hash Algorighm\t%s", hashNames[r.HashAlgorithm])
	totalPasswords, _ := lineCounter(r.InputFile)
	bp("Total Passwords\t%d", totalPasswords)
	bp("Parallel Workers\t%d", r.WorkersCount)
	if r.DecoratorFunction != nil {
		bp("Decorator Func\t%+v", r.DecoratorFunction)
	}
	fmt.Println()
}

// Start the rockyrainbow process
func (r *RockyRainbow) Start() (err error) {
	if r.outFile, err = os.Create(r.OutputFile); err != nil {
		return
	}
	if r.inFile, err = os.Open(r.InputFile); err != nil {
		return
	}
	defer func() {
		r.inFile.Close()
		r.outFile.Close()
	}()
	r.displayConf()

	p("Loading jobs queue")
	go r.queuer()

	p("Loading workers")
	for i := 0; i < r.WorkersCount; i++ {
		go r.worker()
	}

	p("Waiting for workers to complete, type ENTER for current status...")
	go statusLoop(&r.status)
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
	var h hash.Hash

	switch r.HashAlgorithm {
	case MD5:
		h = md5.New()
		break
	case SHA1:
		h = sha1.New()
		break
	case SHA256:
		h = sha256.New()
		break
	case SHA512:
		h = sha512.New()
		break
	case NTLM:
		h = ntlm.New()
		break
	default:
		panic("Invalid hash algorithm")
	}
	for msg := range r.msgs {
		h.Reset()
		msgByteSlice := []byte(msg)

		if r.DecoratorFunction != nil {
			msgByteSlice = r.DecoratorFunction(msgByteSlice)
		}

		if r.status {
			p("Current status {password: %s, iteration: %d}", msg, i)
			r.status = false
		}
		h.Write(msgByteSlice)
		r.m.Lock()
		r.outFile.WriteString(
			fmt.Sprintf(
				"%s:%s\n",
				msg,
				hex.EncodeToString(h.Sum(nil)),
			),
		)
		r.m.Unlock()
		i++
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

func statusLoop(status *bool) {
	r := bufio.NewReader(os.Stdin)
	for {
		r.ReadByte()
		*status = true
	}
}

func p(format string, a ...interface{}) {
	t := time.Now()
	fmt.Printf("[%02d:%02d:%02d] ", t.Hour(), t.Minute(), t.Second())
	fmt.Printf(format+"\n", a...)
}
