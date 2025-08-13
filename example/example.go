/*

Exciting Licence Info.....

This file is part of fpReaper.

# Lee's Shitheads Prohibited Licence (loosely based on the BSD simplified licence)
Copyright 2021 Lee Brotherston
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. You are not a member of law enforcement, and you do not work for any government or private organization that conducts or aids surveillance (e.g., signals intelligence, Palantir).
4. You are not associated with any groups which are aligned with Racist, Homophobic, Transphobic, TERF, Mysogynistic, "Pro Life" (anti-womens-choice), or other shithead values.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/LeeBrotherston/dactyloscopy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

func doSniff(device string, file string) error {
	var (
		handle gopacket.PacketDataSource
		err    error
	)
	if len(file) > 0 {
		pcapFile, err := os.Open(file)
		if err != nil {
			return err
		}
		r, err := pcapgo.NewReader(pcapFile)
		if err != nil {
			return err
		}
		handle = r
	} else if len(device) > 0 {
		return fmt.Errorf("live capture not supported in Go-native mode; use a pcap file")
	} else {
		return fmt.Errorf("need a file or interface")
	}
	defer func() {
		if c, ok := handle.(interface{ Close() error }); ok {
			c.Close()
		}
	}()

	ip4defragger := ip4defrag.NewIPv4Defragmenter()
	streamFactory := &tlsStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)

	for packet := range packetSource.Packets() {
		// IP defragmentation
		if net4 := packet.NetworkLayer(); net4 != nil {
			if ipv4, ok := net4.(*layers.IPv4); ok {
				newIPv4, err := ip4defragger.DefragIPv4(ipv4)
				if err != nil {
					log.Printf("IPv4 defrag error: %v", err)
					continue
				}
				if newIPv4 == nil {
					continue // waiting for more fragments
				}
				//packet = packet
			}
		}
		// TCP reassembly
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			continue
		}
		// UDP and others: process as before
		if incompletePacket(packet) {
			continue
		}

		if len(packet.ApplicationLayer().Payload()) < 50 {
			continue
		}

		if err = dactyloscopy.IsClientHello(packet.ApplicationLayer().Payload()); err == nil {
			var clientHello dactyloscopy.Fingerprint
			err = clientHello.ProcessClientHello(packet.ApplicationLayer().Payload())
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			}

			output, err := json.Marshal(clientHello)
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", output)
		}
	}
	return nil
}

func incompletePacket(packet gopacket.Packet) bool {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		//log.Printf("missing network layer")
		return true
	}
	if len(netLayer.LayerPayload()) == 0 {
		//log.Printf("empty network layer")
		return true
	}

	transLayer := packet.TransportLayer()
	if transLayer == nil {
		//log.Printf("missing transport layer")
		return true
	}
	if len(transLayer.LayerPayload()) == 0 {
		//log.Printf("empty transport layer")
		return true
	}

	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		//log.Printf("missing application layer")
		return true
	}

	payloadLen := uint16(len(appLayer.Payload()))
	if payloadLen < 60 {
		//log.Printf("insufficient payload")
		return true
	}

	if v4, ok := netLayer.(*layers.IPv4); ok {
		if v4.Length > payloadLen {
			//log.Printf("length mismatch: %d %d", v4.Length, payloadLen)
			return true
		}
	}
	return false
}

func main() {
	intStr := flag.String("i", "en0", "interface to sniff")
	file := flag.String("f", "", "pcap file")
	flag.Parse()

	doSniff(*intStr, *file)
}

// TLS stream factory and stream for TCP reassembly

type tlsStreamFactory struct{}

func (f *tlsStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go processTLSStream(&r)
	return &r
}

func processTLSStream(r *tcpreader.ReaderStream) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			var clientHello dactyloscopy.Fingerprint
			err = clientHello.ProcessClientHello(buf[:n])
			if err == nil {
				output, _ := json.Marshal(clientHello)
				fmt.Printf("%s\n", output)
			}
		}
	}
}
