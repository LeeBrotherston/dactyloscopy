module example

go 1.23.0

toolchain go1.24.3

replace github.com/LeeBrotherston/dactyloscopy => ./../

require (
	github.com/LeeBrotherston/dactyloscopy v0.0.0-20241113013421-e4efbb39c13b
	github.com/google/gopacket v1.1.19
)

require (
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)
