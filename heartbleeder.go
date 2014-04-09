package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/titanous/heartbleeder/tls"
)


func check(host string) {
	log.Println(host)

	if !strings.Contains(host, ":") {
		host += ":443"
	}
	c, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Printf("Error connecting to %s: %s\n", host, err)
		return
	}

	quit := make(chan bool)
	go timeout(host, quit)
	//quit <- true

	_, _, err = c.Heartbeat(32, nil)
	switch err {
	case nil:
		fmt.Printf("INSECURE - %s has the heartbeat extension enabled and is vulnerable\n", host)
		quit <- true
		return
	case tls.ErrNoHeartbeat:
		fmt.Printf("SECURE - %s does not have the heartbeat extension enabled\n", host)
		quit <- true
		return
	default:
		fmt.Printf("SECURE - %s has heartbeat extension enabled but is not vulnerable\n", host)
		fmt.Printf("This error happened while processing the heartbeat (almost certainly a good thing): %q\n", err)
		quit <- true
		return
	}
}

func timeout(host string, quit chan bool) {
	time.Sleep(4 * time.Second)

	select {
	case q := <- quit:
		log.Println("quitting", q)
		return
	default:
		fmt.Println("SECURE - timed out while waiting for a response from", host)
	}
}

func main() {
	for _, host := range os.Args[1:] {
		go check(host)
	}

	time.Sleep(10 * time.Second)
	fmt.Println("exiting")
}
