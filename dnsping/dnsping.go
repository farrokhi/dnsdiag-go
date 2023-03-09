//
// Copyright (c) 2016-2023, Babak Farrokhi
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

package main

import (
	"fmt"
	"github.com/pborman/getopt/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/farrokhi/dns"
)

type response struct {
	msg *dns.Msg
	rtt time.Duration
}

func makeServerAddr(host string, port int) string {

	var nameserver string

	if isIP := net.ParseIP(host); isIP != nil {
		nameserver = net.JoinHostPort(host, strconv.Itoa(port))
	} else {
		nameserver = net.JoinHostPort(dns.Fqdn(host), strconv.Itoa(port))
	}

	return nameserver
}

func flagsToText(msg *dns.Msg) (flags string) {

	// QR = 0x8000     (Query Response)
	// AA = 0x0400     (Authoritative Answer)
	// TC = 0x0200     (Truncated Response)
	// RD = 0x0100     (Recursion Desired)
	// RA = 0x0080     (Recursion Available)
	// AD = 0x0020     (Authentic Data)
	// CD = 0x0010     (Checking Disabled)

	if msg.Response {
		flags += " QR"
	}
	if msg.Authoritative {
		flags += " AA"
	}
	if msg.Truncated {
		flags += " TC"
	}
	if msg.RecursionDesired {
		flags += " RD"
	}
	if msg.RecursionAvailable {
		flags += " RA"
	}
	if msg.Zero { // well, this should not happen
		flags += " Z"
	}
	if msg.AuthenticatedData {
		flags += " AD"
	}
	if msg.CheckingDisabled {
		flags += " CD"
	}

	return strings.TrimSpace(flags)
}

func printUsage() {
	fmt.Println("dnsping version 2.1.0")
	fmt.Println("usage: dnsping.py [-46DeFhqTvX] [-i interval] [-s server] [-p port] [-P port] [-S address] [-c count] [-t type] [-w wait] hostname")
	fmt.Println("")
	fmt.Println("-h  --help        Show this help")
	fmt.Println("-q  --quiet       Quiet output. Only header and statistics are displayed.")
	fmt.Println("-v  --verbose     Print actual dns response")
	fmt.Println("-s  --server      DNS server to use (default: first entry from /etc/resolv.conf)")
	fmt.Println("-p  --port        DNS server port number (default: 53 for TCP/UDP, 853 for TLS and QUIC)")
	fmt.Println("-T  --tcp         Use TCP as transport protocol")
	fmt.Println("-X  --tls         Use TLS as transport protocol")
	fmt.Println("-H  --doh         Use HTTPS as transport protocol (DoH)")
	fmt.Println("-Q  --quic        Use QUIC as transport protocol (DoQ)")
	fmt.Println("-4  --ipv4        Use IPv4 as default network protocol")
	fmt.Println("-6  --ipv6        Use IPv6 as default network protocol")
	fmt.Println("-P  --srcport     Query source port number (default: 0)")
	fmt.Println("-S  --srcip       Query source IP address (default: default interface address)")
	fmt.Println("-c  --count       Number of requests to send (default: 10, 0 for infinity)")
	fmt.Println("-r  --norecurse   Enforce non-recursive query by clearing RD (recursion desired) bit")
	fmt.Println("-m  --cache-miss  Force cache miss measurement by prepending a random hostname")
	fmt.Println("-w  --wait        Maximum wait time for a reply (default: 2 seconds)")
	fmt.Println("-i  --interval    Time between each request (default: 1 seconds)")
	fmt.Println("-t  --type        DNS request record type (default: A)")
	fmt.Println("-e  --edns        Disable EDNS0 (default: Enabled)")
	fmt.Println("-D  --dnssec      Enable 'DNSSEC desired' flag in requests. Implies EDNS.")
	fmt.Println("-F  --flags       Display response flags")
	fmt.Println("")
}

func optOverride[T interface{}](opt string, DV *T, V T) {
	if getopt.IsSet(opt) {
		*DV = V
	}
}

func main() {
	var err error
	var exists bool
	var rsp response

	// defaults - to be overridden by CLI options
	var (
		count       uint    = 10
		interval    float64 = 1.0 // seconds
		timeout     int64   = 2   //seconds
		qname       string  = "wikipedia.org"
		server      string  = "9.9.9.9"
		dstport     int     = 53
		proto       string  = "udp"
		qtype       string  = "A"
		noRecurse   bool    = false
		want_dnssec bool    = false
		use_edns    bool    = false
		show_flags  bool    = false
		//use_TCP     bool   = false
	)

	var (
		optHelp  = getopt.BoolLong("help", 'h', "Show this help")
		optQuiet = getopt.BoolLong("quiet", 'q', "Quiet output. Only header and statistics are displayed.")
		//optVerbose = getopt.BoolLong("verbose", 'v', "Print actual dns response")
		optServer  = getopt.StringLong("server", 's', "", "DNS server to use", "server")
		optDstPort = getopt.IntLong("port", 'p', dstport, "DNS server port number (default: 53 for TCP/UDP, 853 for TLS and QUIC)", "port")
		optTCP     = getopt.BoolLong("tcp", 'T', "Use TCP as transport protocol")
		//optTLS       = getopt.BoolLong("tls", 'X', "Use TLS as transport protocol")
		//optDoH       = getopt.BoolLong("doh", 'H', "Use HTTPS as transport protocol (DoH)")
		//optQUIC      = getopt.BoolLong("quic", 'Q', "Use QUIC as transport protocol (DoQ)")
		//optIPv4      = getopt.BoolLong("ipv4", '4', "Use IPv4 as default network protocol")
		//optIPv6      = getopt.BoolLong("ipv6", '6', "Use IPv6 as default network protocol")
		//optSrcPort   = getopt.Int16Long("srcport", 'P', 0, "Query source port number (default: 0)")
		//optSrcIP     = getopt.StringLong("srcip", 'S', "", "Query source IP address (default: default interface address)")
		optCount     = getopt.UintLong("count", 'c', count, "Number of requests to send (default: 10, 0 for infinity)", "count")
		optNoRecurse = getopt.BoolLong("norecurse", 'r', "Enforce non-recursive query by clearing RD (recursion desired) bit")
		//optCacheMiss = getopt.BoolLong("cache-miss", 'm', "Force cache miss measurement by prepending a random hostname")
		optWaitTime = getopt.Int64Long("wait", 'w', timeout, "Maximum wait time for a reply (in seconds)", "timeout")
		//optInterval = getopt.Int64Long("interval", 'i', interval, "Time between each request (in seconds)", "interval")
		optType   = getopt.StringLong("type", 't', qtype, "DNS request record type", "type")
		optEDNS   = getopt.BoolLong("edns", 'e', "Enable EDNS0")
		optDNSSEC = getopt.BoolLong("dnssec", 'D', "Enable 'DNSSEC desired' (DO flag) in requests. Implies EDNS.")
		optFlags  = getopt.BoolLong("flags", 'F', "Display response flags")
	)

	//getopt.SetUsage(printUsage) // use our own help message to keep proper options order

	getopt.FlagLong(&interval, "interval", 'i', "Time between each request (in seconds)", "interval")

	getopt.Parse()

	if getopt.NArgs() < 1 {
		fmt.Println("dnsping: missing hostname")
		getopt.PrintUsage(os.Stderr)
		//printUsage()
		os.Exit(1)
	}

	qname = getopt.Arg(0)

	// I don't rely on getopt to keep/set default values, because I need
	// more flexibility and need to manipulate options
	// e.g. I cannot set default bool to true in getopt.BoolLong()

	optOverride("server", &server, *optServer)
	optOverride("count", &count, *optCount)
	optOverride("type", &qtype, *optType)
	optOverride("norecurse", &noRecurse, *optNoRecurse)
	optOverride("wait", &timeout, *optWaitTime)
	optOverride("edns", &use_edns, *optEDNS)
	optOverride("flags", &show_flags, *optFlags)
	optOverride("port", &dstport, *optDstPort)
	optOverride("dnssec", &want_dnssec, *optDNSSEC)
	//optOverride("interval", &interval, *optInterval)

	if want_dnssec { // EDNS0 is required to set DO bit
		use_edns = true
	}

	if *optTCP {
		//has_TCP = true
		proto = "tcp"
	}

	if *optHelp {
		printUsage()
		os.Exit(0)
	}

	// setup client
	c := new(dns.Client)
	c.Net = proto
	c.DialTimeout = time.Duration(timeout) * time.Second
	c.ReadTimeout = time.Duration(timeout) * time.Second
	c.WriteTimeout = time.Duration(timeout) * time.Second

	// setup server
	nameserver := makeServerAddr(server, dstport)

	// Setup Request
	m := new(dns.Msg)
	m.MsgHdr = dns.MsgHdr{}
	m.Question = make([]dns.Question, 1)
	m.Opcode = dns.OpcodeQuery
	m.RecursionDesired = !noRecurse
	if use_edns {
		m.SetEdns0(8192, want_dnssec)
	}

	// how to set local address
	//
	//         if *laddr != "" {
	//                c.Dialer = &net.Dialer{Timeout: c.DialTimeout}
	//                ip := net.ParseIP(*laddr)
	//                if *tcp {
	//                        c.Dialer.LocalAddr = &net.TCPAddr{IP: ip}
	//                } else {
	//                        c.Dialer.LocalAddr = &net.UDPAddr{IP: ip}
	//                }
	//        }

	m.Question[0].Name = dns.Fqdn(qname)
	m.Question[0].Qclass = dns.ClassINET
	m.Question[0].Qtype, exists = dns.StringToType[qtype]
	if !exists {
		fmt.Printf("Error: Invalid record type: %s\n", qtype)
		os.Exit(1)
	}

	fmt.Printf("dnsping DNS: %v, hostname: %v, proto: %v, type: %v, flags: [%s]\n", nameserver, qname, proto, *optType, flagsToText(m))

	//s := m.Question[0].
	for i := uint(0); i < count; i++ {
		m.Id = dns.Id() // Need new ID for each request
		rsp.msg, rsp.rtt, err = c.Exchange(m, nameserver)
		switch {
		case err != nil:
			fmt.Println(err)
		case rsp.msg != nil && !*optQuiet:
			fmt.Printf("%d bytes from %s: seq=%-3d time=%-7.3f ms", rsp.msg.PktLen, server, i+1, rsp.rtt.Seconds()*1000)
			if show_flags {
				fmt.Printf(" [%s]  %s", flagsToText(rsp.msg), dns.RcodeToString[rsp.msg.Rcode])
			}
			fmt.Printf("\n")
		default:
			panic("empty result")
		}

		time.Sleep((time.Duration(interval) * time.Second) - rsp.rtt) // return immediately when duration is negative
	}
	fmt.Printf("\n--- %s dnsping statistics ---\n", server)

}
