package main

import (
    //"fmt"
    "bufio"
    "log"
    "os"
    "crypto/md5"
    "io"
    "runtime"
)

var done = make(chan bool)
var msgs = make(chan string)

func rainbowProduce() {
    file, err := os.Open(os.Args[1])
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
    done <- true
}

func rainbowConsume() {
    for msg := range msgs {
        h := md5.New()
        io.WriteString(h, msg)
        //fmt.Printf("%s:%x\n", msg, h.Sum(nil))
    }
}

func main() {
    runtime.GOMAXPROCS(16)

    go rainbowProduce()
    for i := 0; i < 10; i++ {
        go rainbowConsume()
    }
    <-done
}
