module example

go 1.24.0

toolchain go1.24.3

replace github.com/LeeBrotherston/dactyloscopy => ./../

require (
	github.com/LeeBrotherston/dactyloscopy v0.0.0-20250813182441-4b6fb1ddec92
	github.com/google/gopacket v1.1.19
)

require (
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
)
