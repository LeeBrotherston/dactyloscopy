package dactyloscopy

import (
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/cryptobyte"
)

func TestProcessClientHello(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantJA3 string
		wantErr bool
	}{
		{
			name:    "Empty input",
			input:   []byte{},
			wantErr: true,
		},
		// Add more test cases here
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &Fingerprint{}
			err := fp.ProcessClientHello(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessClientHello() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fp.JA3 != tt.wantJA3 {
				t.Errorf("JA3 = %v, want %v", fp.JA3, tt.wantJA3)
			}
		})
	}
}

func TestFingerprint_Validate(t *testing.T) {
	tests := []struct {
		name    string
		fp      *Fingerprint
		wantErr bool
	}{
		{
			name: "Valid fingerprint",
			fp: &Fingerprint{
				MessageType: HandshakeType,
				TLSVersion:  VersionTLS12,
				Ciphersuite: []uint16{0x1301, 0x1302},
				Extensions:  []uint16{ExtServerName},
			},
			wantErr: false,
		},
		{
			name: "Invalid message type",
			fp: &Fingerprint{
				MessageType: 0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fp.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSamplePcaps(t *testing.T) {
	counter := 1
	for _, file := range []string{"thing.pcap"} {
		pcapFile, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := pcap.OpenOfflineFile(pcapFile)
		if err != nil {
			t.Fatal(err)
		}

		// Yes yes, I know... But offsetting this to the kernel *drastically* reduces processing time
		err = handle.SetBPFFilter("(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3)) or (ip6[(ip6[52]/16*4)+40]=22 and (ip6[(ip6[52]/16*4+5)+40]=1) and (ip6[(ip6[52]/16*4+9)+40]=3) and (ip6[(ip6[52]/16*4+1)+40]=3)) or ((udp[14] = 6 and udp[16] = 32 and udp[17] = 1) and ((udp[(udp[60]/16*4)+48]=22) and (udp[(udp[60]/16*4)+53]=1) and (udp[(udp[60]/16*4)+57]=3) and (udp[(udp[60]/16*4)+49]=3))) or (proto 41 and ip[26] = 6 and ip[(ip[72]/16*4)+60]=22 and (ip[(ip[72]/16*4+5)+60]=1) and (ip[(ip[72]/16*4+9)+60]=3) and (ip[(ip[72]/16*4+1)+60]=3))")
		if err != nil {
			t.Fatal(err)
		}
		defer handle.Close()

		// Use the handle as a packet source to process all packets
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			t.Logf("processing client hello %d", counter)
			counter++

			payload := packet.ApplicationLayer()
			processHello(t, payload.Payload())
		}
	}
}

func processHello(t *testing.T, data []byte) {
	t.Helper()

	fp := &Fingerprint{}
	err := fp.ProcessClientHello(data)
	if err != nil {
		t.Logf("Oh no, error: %v", err)
		t.FailNow()
	}
	t.Logf("parsed it: %+v", fp)
}

func FuzzProcessClientHello(f *testing.F) {
	// Add initial corpus using known valid inputs
	for _, file := range []string{"thing.pcap"} {
		pcapFile, err := os.Open(file)
		if err != nil {
			f.Fatal(err)
		}
		handle, err := pcap.OpenOfflineFile(pcapFile)
		if err != nil {
			f.Fatal(err)
		}

		// Yes yes, I know... But offsetting this to the kernel *drastically* reduces processing time
		err = handle.SetBPFFilter("(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3)) or (ip6[(ip6[52]/16*4)+40]=22 and (ip6[(ip6[52]/16*4+5)+40]=1) and (ip6[(ip6[52]/16*4+9)+40]=3) and (ip6[(ip6[52]/16*4+1)+40]=3)) or ((udp[14] = 6 and udp[16] = 32 and udp[17] = 1) and ((udp[(udp[60]/16*4)+48]=22) and (udp[(udp[60]/16*4)+53]=1) and (udp[(udp[60]/16*4)+57]=3) and (udp[(udp[60]/16*4)+49]=3))) or (proto 41 and ip[26] = 6 and ip[(ip[72]/16*4)+60]=22 and (ip[(ip[72]/16*4+5)+60]=1) and (ip[(ip[72]/16*4+9)+60]=3) and (ip[(ip[72]/16*4+1)+60]=3))")
		if err != nil {
			f.Fatal(err)
		}
		defer handle.Close()

		// Use the handle as a packet source to process all packets
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			payload := packet.ApplicationLayer()
			f.Add(payload.Payload())
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fp := &Fingerprint{}
		// We only care that this doesn't panic, in this context errors are graceful handling
		_ = fp.ProcessClientHello(data)
	})
}

func TestReadXLengthYVal(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		lengthSize int
		valueSize  int
		wantVal    []uint64
	}{
		{
			name:       "Valid input len 1",
			input:      []byte{0x03, 0x05, 0x01, 0x02},
			lengthSize: 1,
			valueSize:  1,
			wantVal:    []uint64{0x05, 0x01, 0x02},
		},
		{
			name:       "Valid input len 2",
			input:      []byte{0x00, 0x03, 0x05, 0x01, 0x02},
			lengthSize: 2,
			valueSize:  1,
			wantVal:    []uint64{0x05, 0x01, 0x02},
		},
		{
			name:       "Valid input size 2",
			input:      []byte{0x00, 0x04, 0x05, 0x01, 0x02, 0x07},
			lengthSize: 2,
			valueSize:  2,
			wantVal:    []uint64{0x0501, 0x0207},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataBlock := cryptobyte.String(tt.input)
			var output []uint64

			err := readXLengthYVal(&dataBlock, &output, tt.lengthSize, tt.valueSize)
			if err != nil {
				t.Errorf("readXLengthYVal() error = %v", err)
				return
			}

			assert.Equal(t, output, tt.wantVal, "readXLengthYVal() mismatch")
		})
	}
}
