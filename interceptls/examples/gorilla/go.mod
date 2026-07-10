module github.com/LeeBrotherston/dactyloscopy/interceptls/examples/gorilla

go 1.26.2

replace github.com/LeeBrotherston/dactyloscopy => ../../../../dactyloscopy

replace github.com/LeeBrotherston/dactyloscopy/interceptls => ../../../interceptls

require golang.org/x/crypto v0.52.0 // indirect

require (
	github.com/gorilla/mux v1.8.1
	github.com/leebrotherston/dactyloscopy/interceptls v0.0.0-20260516234205-901eae120cd2
)

require github.com/LeeBrotherston/dactyloscopy v0.0.0-20260517020304-93c34010ce4f // indirect
