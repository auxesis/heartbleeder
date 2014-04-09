package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "strings"
    "time"
	"sync"
    "github.com/titanous/heartbleeder/tls"
)

func check(host string, timeout *time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()

    if !strings.Contains(host, ":") {
        host += ":443"
    }
    c, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
    if err != nil {
        log.Printf("Error connecting to %s: %s\n", host, err)
        return
    }

    err = c.WriteHeartbeat(1, nil)
    if err == tls.ErrNoHeartbeat {
        fmt.Printf("SECURE - %s does not have the heartbeat extension enabled\n", host)
        return
    }
    if err != nil {
        fmt.Println("UNKNOWN - Heartbeat enabled, but there was an error writing the payload:", err)
		return
    }

    readErr := make(chan error)
    go func() {
        _, _, err := c.ReadHeartbeat()
        readErr <- err
    }()

    select {
    case err := <-readErr:
        if err == nil {
            fmt.Printf("VULNERABLE - %s has the heartbeat extension enabled and is vulnerable to CVE-2014-0160\n", host)
            return
        }
        fmt.Printf("SECURE - %s has heartbeat extension enabled but is not vulnerable\n", host)
        fmt.Printf("This error happened while reading the response to the malformed heartbeat (almost certainly a good thing): %q\n", err)
    case <-time.After(*timeout):
        fmt.Printf("SECURE - %s has the heartbeat extension enabled, but timed out after a malformed heartbeat (this likely means that it is not vulnerable)\n", host)
    }
}

func main() {
    timeout := flag.Duration("timeout", 5*time.Second, "Timeout after sending heartbeat")
    flag.Usage = func() {
        fmt.Printf("Usage: %s [options] host[:443]\n", os.Args[0])
        fmt.Println("Options:")
        flag.PrintDefaults()
    }
    flag.Parse()

	wg := new(sync.WaitGroup)

	for _, host := range os.Args[1:] {
		if strings.HasPrefix(host, "-timeout") { continue }
		wg.Add(1)
		go check(host, timeout, wg)
	}

	log.Println("Waiting for timeouts")
	wg.Wait()
	log.Println("All workers finished. Exiting.")
}
