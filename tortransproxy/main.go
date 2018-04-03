package main

import (
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	tport := flag.Int("transport", 1337,
		"the port that iptables will be redirecting connections to")
	flag.Parse()

	la, _ := net.ResolveTCPAddr("tcp6", fmt.Sprintf("[::]:%d", *tport))
	l, err := net.ListenTCP("tcp6", la)
	if err != nil {
		log.Fatalf("Unable to listen on the transparent port %s",
			err.Error())
	}

	failurecount := 0
	for {
		c, err := l.AcceptTCP()
		if err != nil {
			if failurecount != 50 {
				failurecount++
			} else {
				log.Printf("Unable to accept connection! %s", err.Error())
			}
			time.Sleep(time.Millisecond * time.Duration(failurecount*10))
			continue
		}
		failurecount = 0

		go handleConn(c)
	}
}

func handleConn(c *net.TCPConn) {
	// first, let's recover the address
	tc, fd, err := realServerAddress(c)
	defer c.Close()
	defer fd.Close()

	if err != nil {
		log.Printf("Unable to recover address %s", err.Error())
		return
	}

	toraddr := tc.IP[6:]
	toronionaddr :=
		fmt.Sprintf("%s.onion", base32.StdEncoding.EncodeToString(toraddr))

	log.Printf("Connection from %s to %s:%d",
		c.RemoteAddr().String(), toronionaddr, tc.Port)

	d, err := proxy.SOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
	if err != nil {
		log.Printf("Unable to recover address %s", err.Error())
		return
	}

	torconn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", toronionaddr, tc.Port))
	if err != nil {
		log.Printf("Tor conncetion error %s", err.Error())
		return
	}

	go io.Copy(torconn, fd)
	io.Copy(fd, torconn)
}
