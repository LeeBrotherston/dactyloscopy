package dactyloscopy

func GetIANAExtension(extension uint16) string {
	return IanaExtension(extension).String()
}

//go:generate stringer -type=IanaExtension
type IanaExtension uint16

const (
	server_name                            IanaExtension = 0
	max_fragment_length                    IanaExtension = 1
	client_certificate_url                 IanaExtension = 2
	trusted_ca_keys                        IanaExtension = 3
	truncated_hmac                         IanaExtension = 4
	status_request                         IanaExtension = 5
	user_mapping                           IanaExtension = 6
	client_authz                           IanaExtension = 7
	server_authz                           IanaExtension = 8
	cert_type                              IanaExtension = 9
	supported_groups                       IanaExtension = 10
	ec_point_formats                       IanaExtension = 11
	srp                                    IanaExtension = 12
	signature_algorithms                   IanaExtension = 13
	use_srtp                               IanaExtension = 14
	heartbeat                              IanaExtension = 15
	application_layer_protocol_negotiation IanaExtension = 16
	status_request_v2                      IanaExtension = 17
	signed_certificate_timestamp           IanaExtension = 18
	client_certificate_type                IanaExtension = 19
	server_certificate_type                IanaExtension = 20
	padding                                IanaExtension = 21
	encrypt_then_mac                       IanaExtension = 22
	extended_master_secret                 IanaExtension = 23
	token_binding                          IanaExtension = 24
	cached_info                            IanaExtension = 25
	tls_lts                                IanaExtension = 26
	compress_certificate                   IanaExtension = 27
	record_size_limit                      IanaExtension = 28
	pwd_protect                            IanaExtension = 29
	pwd_clear                              IanaExtension = 30
	password_salt                          IanaExtension = 31
	ticket_pinning                         IanaExtension = 32
	tls_cert_with_extern_psk               IanaExtension = 33
	delegated_credential                   IanaExtension = 34
	session_ticket                         IanaExtension = 35
	TLMSP                                  IanaExtension = 36
	TLMSP_proxying                         IanaExtension = 37
	TLMSP_delegate                         IanaExtension = 38
	supported_ekt_ciphers                  IanaExtension = 39
	pre_shared_key                         IanaExtension = 41
	early_data                             IanaExtension = 42
	supported_versions                     IanaExtension = 43
	cookie                                 IanaExtension = 44
	psk_key_exchange_modes                 IanaExtension = 45
	certificate_authorities                IanaExtension = 47
	oid_filters                            IanaExtension = 48
	post_handshake_auth                    IanaExtension = 49
	signature_algorithms_cert              IanaExtension = 50
	key_share                              IanaExtension = 51
	transparency_info                      IanaExtension = 52
	connection_id_deprecated               IanaExtension = 53
	connection_id                          IanaExtension = 54
	external_id_hash                       IanaExtension = 55
	external_session_id                    IanaExtension = 56
	quic_transport_parameters              IanaExtension = 57
	ticket_request                         IanaExtension = 58
	dnssec_chain                           IanaExtension = 59
	sequence_number_encryption_algorithms  IanaExtension = 60
	rrc                                    IanaExtension = 61
	tls_flags                              IanaExtension = 62
	ech_outer_extensions                   IanaExtension = 64768
	encrypted_client_hello                 IanaExtension = 65037
	PrivateUse                             IanaExtension = 65280
	renegotiation_info                     IanaExtension = 65281
)

/*
var ianaExtensions = map[uint16]string{
	0:     "server_name",
	1:     "max_fragment_length",
	2:     "client_certificate_url",
	3:     "trusted_ca_keys",
	4:     "truncated_hmac",
	5:     "status_request",
	6:     "user_mapping",
	7:     "client_authz",
	8:     "server_authz",
	9:     "cert_type",
	10:    "supported_groups",
	11:    "ec_point_formats",
	12:    "srp",
	13:    "signature_algorithms",
	14:    "use_srtp",
	15:    "heartbeat",
	16:    "application_layer_protocol_negotiation",
	17:    "status_request_v2",
	18:    "signed_certificate_timestamp",
	19:    "client_certificate_type",
	20:    "server_certificate_type",
	21:    "padding",
	22:    "encrypt_then_mac",
	23:    "extended_master_secret",
	24:    "token_binding",
	25:    "cached_info",
	26:    "tls_lts",
	27:    "compress_certificate",
	28:    "record_size_limit",
	29:    "pwd_protect",
	30:    "pwd_clear",
	31:    "password_salt",
	32:    "ticket_pinning",
	33:    "tls_cert_with_extern_psk",
	34:    "delegated_credential",
	35:    "session_ticket",
	36:    "TLMSP",
	37:    "TLMSP_proxying",
	38:    "TLMSP_delegate",
	39:    "supported_ekt_ciphers",
	40:    "Reserved",
	41:    "pre_shared_key",
	42:    "early_data",
	43:    "supported_versions",
	44:    "cookie",
	45:    "psk_key_exchange_modes",
	46:    "Reserved",
	47:    "certificate_authorities",
	48:    "oid_filters",
	49:    "post_handshake_auth",
	50:    "signature_algorithms_cert",
	51:    "key_share",
	52:    "transparency_info",
	53:    "connection_id (deprecated)",
	54:    "connection_id",
	55:    "external_id_hash",
	56:    "external_session_id",
	57:    "quic_transport_parameters",
	58:    "ticket_request",
	59:    "dnssec_chain",
	60:    "sequence_number_encryption_algorithms",
	61:    "rrc",
	62:    "tls_flags",
	2570:  "Reserved",
	6682:  "Reserved",
	10794: "Reserved",
	14906: "Reserved",
	19018: "Reserved",
	23130: "Reserved",
	27242: "Reserved",
	31354: "Reserved",
	35466: "Reserved",
	39578: "Reserved",
	43690: "Reserved",
	47802: "Reserved",
	51914: "Reserved",
	56026: "Reserved",
	60138: "Reserved",
	64250: "Reserved",
	64768: "ech_outer_extensions",
	65037: "encrypted_client_hello",
	65280: "Reserved for Private Use",
	65281: "renegotiation_info",
}
*/
