package main

import (
	"encoding/base32"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func main() {
	dnsbase := flag.String("domain", "tor6.flm.me.uk", "the domain you want to top on")
	listen := flag.String("listen", "127.0.0.1:553", "the port to listen on")
	flag.Parse()

	listens, err := net.ListenPacket("udp4", *listen)
	if err != nil {
		log.Fatalf("failed to listen on UDP %s / %s", *listen, err.Error())
	}

	for {
		dnsin := make([]byte, 1500)
		inbytes, inaddr, err := listens.ReadFrom(dnsin)

		inmsg := &dns.Msg{}

		if unpackErr := inmsg.Unpack(dnsin[0:inbytes]); unpackErr != nil {
			log.Printf("Unable to unpack DNS request %s", err.Error())
			continue
		}

		if len(inmsg.Question) != 1 {
			log.Printf("More than one quesion in query (%d), droppin %+v", len(inmsg.Question), inmsg)
			continue
		}

		iqn := strings.ToLower(inmsg.Question[0].Name)

		if !strings.Contains(iqn, *dnsbase) {
			log.Printf("question is not for us '%s' vs expected '%s'", iqn, *dnsbase)
			continue
		}

		outmsg := &dns.Msg{}

		iqn = strings.ToUpper(inmsg.Question[0].Name)

		queryname := strings.Replace(
			iqn, fmt.Sprintf(".%s.", strings.ToUpper(*dnsbase)), "", 1)

		b32, err := base32.StdEncoding.DecodeString(queryname)

		if err != nil || len(b32) != 10 {
			outmsg.Id = inmsg.Id
			outmsg = inmsg.SetReply(outmsg)
			outmsg.Rcode = dns.RcodeServerFailure

			outputb, err := outmsg.Pack()

			if err != nil {
				log.Printf("unable to pack response to thing")
				continue
			}

			listens.WriteTo(outputb, inaddr)
			continue
		}

		barr := make([]byte, 0)
		barr = append(barr, 0x2a, 0x0c, 0x2f, 0x07, 0xFE, 0xD5)
		barr = append(barr, b32...)
		bip := net.IP(barr)

		outmsg.Id = inmsg.Id
		outmsg = inmsg.SetReply(outmsg)
		iqn = inmsg.Question[0].Name
		outmsg.Answer = make([]dns.RR, 1)
		outmsg.Answer[0] = &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   iqn,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    2147483646},
			AAAA: bip,
		}
		outputb, err := outmsg.Pack()

		if err != nil {
			log.Printf("unable to pack response to thing %s", err.Error())
			continue
		}

		listens.WriteTo(outputb, inaddr)
	}
}
