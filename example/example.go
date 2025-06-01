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
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

func doSniff(device string, file string) error {
	var (
		handle *pcap.Handle
		err    error
	)
	if len(file) > 0 {
		pcapFile, err := os.Open(file)
		if err != nil {
			return err
		}
		handle, err = pcap.OpenOfflineFile(pcapFile)
		if err != nil {
			return err
		}
	} else if len(device) > 0 {
		// Open device
		// the 0 and true refer to snaplen and promisc mode.  For now we always want these.
		handle, err = pcap.OpenLive(device, 0, true, pcap.BlockForever)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("need a file or interface")
	}
	// Yes yes, I know... But offsetting this to the kernel *drastically* reduces processing time
	//err = handle.SetBPFFilter("((tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3)) or (ip6[(ip6[52]/16*4)+40]=22 and (ip6[(ip6[52]/16*4+5)+40]=1) and (ip6[(ip6[52]/16*4+9)+40]=3) and (ip6[(ip6[52]/16*4+1)+40]=3)) or ((udp[14] = 6 and udp[16] = 32 and udp[17] = 1) and ((udp[(udp[60]/16*4)+48]=22) and (udp[(udp[60]/16*4)+53]=1) and (udp[(udp[60]/16*4)+57]=3) and (udp[(udp[60]/16*4)+49]=3))) or (proto 41 and ip[26] = 6 and ip[(ip[72]/16*4)+60]=22 and (ip[(ip[72]/16*4+5)+60]=1) and (ip[(ip[72]/16*4+9)+60]=3) and (ip[(ip[72]/16*4+1)+60]=3))) or (ip[6:2] & 0x1fff != 0)")
	//if err != nil {
	//	return err
	//}
	defer handle.Close()

	ip4defragger := ip4defrag.NewIPv4Defragmenter()
	streamFactory := &tlsStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

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
