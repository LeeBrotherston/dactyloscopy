package main

type fingerprint struct {
	JA3Digest string
	LB1Digest string
	Name      string
}

var static_fingerprints = []fingerprint{{
	JA3Digest: "579ccef312d18482fc42e2b822ca2430",
	LB1Digest: "5d75e7f9e50ed137cd48d5ea5e9ebe36",
	Name:      "Firefox 115.0.2",
}, {
	JA3Digest: "366d007990af3b100f90c88fcff57a8a",
	LB1Digest: "7a8af08e01539e5863f202db34e5a727",
	Name:      "Zoom",
}}

// InitFPDB creates fingerprint DB structures, currently separated into JA3 and LB1 "tables"
func InitFPDB(fplist []fingerprint) (map[string]fingerprint, map[string]fingerprint) {
	return initFPDBJA3(fplist), initFPDBLB1(fplist)
}

func initFPDBJA3(fp []fingerprint) map[string]fingerprint {
	output := map[string]fingerprint{}
	for _, y := range fp {
		output[y.JA3Digest] = y
	}
	return output
}

func initFPDBLB1(fp []fingerprint) map[string]fingerprint {
	output := map[string]fingerprint{}
	for _, y := range fp {
		output[y.LB1Digest] = y
	}
	return output
}
