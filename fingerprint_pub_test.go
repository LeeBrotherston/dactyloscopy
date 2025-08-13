package dactyloscopy_test

import (
	"os"
	"testing"

	"github.com/LeeBrotherston/dactyloscopy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
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
			fp := &dactyloscopy.Fingerprint{}
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
		fp      *dactyloscopy.Fingerprint
		wantErr bool
	}{
		{
			name: "Valid fingerprint",
			fp: &dactyloscopy.Fingerprint{
				MessageType: dactyloscopy.HandshakeType,
				TLSVersion:  dactyloscopy.VersionTLS12,
				Ciphersuite: []uint16{0x1301, 0x1302},
				Extensions:  []uint16{dactyloscopy.ExtServerName},
			},
			wantErr: false,
		},
		{
			name: "Invalid message type",
			fp: &dactyloscopy.Fingerprint{
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
	for _, file := range []string{"thing2.pcapng"} {
		pcapFile, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		r, err := pcapgo.NewNgReader(pcapFile, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			t.Fatal(err)
		}
		defer pcapFile.Close()

		packetSource := gopacket.NewPacketSource(r, r.LinkType())
		for packet := range packetSource.Packets() {
			if err := dactyloscopy.IsClientHello(packet.ApplicationLayer().Payload()); err != nil {
				continue
			}
			t.Logf("processing client hello %d", counter)
			counter++

			payload := packet.ApplicationLayer()
			if payload != nil {
				processHello(t, payload.Payload())
			}
		}
	}
}

func processHello(t *testing.T, data []byte) {
	t.Helper()

	fp := &dactyloscopy.Fingerprint{}
	err := fp.ProcessClientHello(data)
	if err != nil {
		t.Logf("Oh no, error: %v", err)
		t.FailNow()
	}
	t.Logf("parsed it: %+v", fp)
}

func FuzzProcessClientHello(f *testing.F) {
	// Add initial corpus using known valid inputs
	for _, file := range []string{"thing2.pcapng"} {
		pcapFile, err := os.Open(file)
		if err != nil {
			f.Fatal(err)
		}
		r, err := pcapgo.NewNgReader(pcapFile, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Fatal(err)
		}
		defer pcapFile.Close()

		packetSource := gopacket.NewPacketSource(r, r.LinkType())
		for packet := range packetSource.Packets() {
			payload := packet.ApplicationLayer()
			if payload != nil {
				f.Add(payload.Payload())
			}
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fp := &dactyloscopy.Fingerprint{}
		// We only care that this doesn't panic, in this context errors are graceful handling
		_ = fp.ProcessClientHello(data)
	})
}
