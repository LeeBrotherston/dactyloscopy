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
	"fmt"
	"os"

	"github.com/LeeBrotherston/dactyloscopy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func doSniff(device string) error {

	// Open device
	// the 0 and true refer to snaplen and promisc mode.  For now we always want these.
	handle, err := pcap.OpenLive(device, 0, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	// Yes yes, I know... But offsetting this to the kernel *drastically* reduces processing time
	err = handle.SetBPFFilter("(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3)) or (ip6[(ip6[52]/16*4)+40]=22 and (ip6[(ip6[52]/16*4+5)+40]=1) and (ip6[(ip6[52]/16*4+9)+40]=3) and (ip6[(ip6[52]/16*4+1)+40]=3)) or ((udp[14] = 6 and udp[16] = 32 and udp[17] = 1) and ((udp[(udp[60]/16*4)+48]=22) and (udp[(udp[60]/16*4)+53]=1) and (udp[(udp[60]/16*4)+57]=3) and (udp[(udp[60]/16*4)+49]=3))) or (proto 41 and ip[26] = 6 and ip[(ip[72]/16*4)+60]=22 and (ip[(ip[72]/16*4+5)+60]=1) and (ip[(ip[72]/16*4+9)+60]=3) and (ip[(ip[72]/16*4+1)+60]=3))")
	if err != nil {
		return err
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		var clientHello dactyloscopy.Fingerprint
		payload := packet.ApplicationLayer()

		err = clientHello.ProcessClientHello(payload.Payload())
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}

		output, err := json.Marshal(clientHello)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", output)
		//fingerprintOutput, fpDetail, fpHash := dactyloscopy.TLSFingerprint(payload.Payload(), fingerprintDBNew)

	}
	return nil
}

func main() {
	doSniff(os.Args[1])
}
