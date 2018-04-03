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

	if !isAllowedPort(tc.Port) {
		log.Printf("Disallowed connection from %s to %s:%d due to port block",
			c.RemoteAddr().String(), toronionaddr, tc.Port)
		return
	}

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

// nicked from https://src.chromium.org/viewvc/chrome/trunk/src/net/base/net_util.cc
var allowedPorts = []int{
	1,    // tcpmux
	7,    // echo
	9,    // discard
	11,   // systat
	13,   // daytime
	15,   // netstat
	17,   // qotd
	19,   // chargen
	20,   // ftp data
	21,   // ftp access
	22,   // ssh
	23,   // telnet
	25,   // smtp
	37,   // time
	42,   // name
	43,   // nicname
	53,   // domain
	77,   // priv-rjs
	79,   // finger
	87,   // ttylink
	95,   // supdup
	101,  // hostriame
	102,  // iso-tsap
	103,  // gppitnp
	104,  // acr-nema
	109,  // pop2
	110,  // pop3
	111,  // sunrpc
	113,  // auth
	115,  // sftp
	117,  // uucp-path
	119,  // nntp
	123,  // NTP
	135,  // loc-srv /epmap
	139,  // netbios
	143,  // imap2
	179,  // BGP
	389,  // ldap
	465,  // smtp+ssl
	512,  // print / exec
	513,  // login
	514,  // shell
	515,  // printer
	526,  // tempo
	530,  // courier
	531,  // chat
	532,  // netnews
	540,  // uucp
	556,  // remotefs
	563,  // nntp+ssl
	587,  // stmp?
	601,  // ??
	636,  // ldap+ssl
	993,  // ldap+ssl
	995,  // pop3+ssl
	2049, // nfs
	3659, // apple-sasl / PasswordServer
	4045, // lockd
	6000, // X11
	6665, // Alternate IRC [Apple addition]
	6666, // Alternate IRC [Apple addition]
	6667, // Standard IRC [Apple addition]
	6668, // Alternate IRC [Apple addition]
	6669, // Alternate IRC [Apple addition]
}

func isAllowedPort(port int) bool {
	for _, good := range allowedPorts {
		if port == good {
			return true
		}
	}
	return false
}
