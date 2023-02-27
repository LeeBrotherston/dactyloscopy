module example

go 1.18

replace github.com/LeeBrotherston/dactyloscopy => ./../

require (
	github.com/LeeBrotherston/dactyloscopy v0.0.0-20211004030734-27f81f4ef3d5
	github.com/google/gopacket v1.1.19
)

require (
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
)
