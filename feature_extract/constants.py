PRETTY_NAMES = {
    'alert_level':{
        1: 'warning',
        2: 'fatal'
    },
    'alert_description': {
        0: 'close_notify',
        10: 'unexpected_message',
        20: 'bad_record_mac',
        21: 'decryption_failed',
        22: 'record_overflow',
        30: 'decompression_failure',
        40: 'handshake_failure',
        41: 'no_certificate',
        42: 'bad_certificate',
        43: 'unsupported_certificate',
        44: 'certificate_revoked',
        45: 'certificate_expired',
        46: 'certificate_unknown',
        47: 'illegal_parameter',
        48: 'unknown_ca',
        49: 'access_denied',
        50: 'decode_error',
        51: 'decrypt_error',
        60: 'export_restriction',
        70: 'protocol_version',
        71: 'insufficient_security',
        80: 'internal_error',
        86: 'inappropriate_fallback',
        90: 'user_canceled',
        100: 'no_renegotiation',
        110: 'unsupported_extension',
        111: 'certificate_unobtainable',
        112: 'unrecognized_name',
        113: 'bad_certificate_status_response',
        114: 'bad_certificate_hash_value',
        115: 'unknown_psk_identity'
    },
    'cipher_suites': {
        0x010080: 'SSL_CK_RC4_128_WITH_MD5',
        0x020080: 'SSL_CK_RC4_128_EXPORT40_WITH_MD5',
        0x030080: 'SSL_CK_RC2_128_CBC_WITH_MD5	',
        0x040080: 'SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5',
        0x050080: 'SSL_CK_IDEA_128_CBC_WITH_MD5',
        0x060040: 'SSL_CK_DES_64_CBC_WITH_MD5',
        0x0700C0: 'SSL_CK_DES_192_EDE3_CBC_WITH_MD5',
        0x080080: 'SSL_CK_RC4_64_WITH_MD5',
        0x00: 'TLS_NULL_WITH_NULL_NULL',
        0x01: 'TLS_RSA_WITH_NULL_MD5',
        0x02: 'TLS_RSA_WITH_NULL_SHA',
        0x03: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
        0x04: 'TLS_RSA_WITH_RC4_128_MD5',
        0x05: 'TLS_RSA_WITH_RC4_128_SHA',
        0x06: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
        0x07: 'TLS_RSA_WITH_IDEA_CBC_SHA',
        0x08: 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
        0x09: 'TLS_RSA_WITH_DES_CBC_SHA',
        0x0A: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        0x0B: 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
        0x0C: 'TLS_DH_DSS_WITH_DES_CBC_SHA',
        0x0D: 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
        0x0E: 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
        0x0F: 'TLS_DH_RSA_WITH_DES_CBC_SHA',
        0x10: 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
        0x11: 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
        0x12: 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
        0x13: 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
        0x14: 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
        0x15: 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
        0x16: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
        0x17: 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
        0x18: 'TLS_DH_anon_WITH_RC4_128_MD5',
        0x19: 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
        0x1A: 'TLS_DH_anon_WITH_DES_CBC_SHA',
        0x1B: 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
        0x1E: 'TLS_KRB5_WITH_DES_CBC_SHA',
        0x1F: 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
        0x20: 'TLS_KRB5_WITH_RC4_128_SHA',
        0x21: 'TLS_KRB5_WITH_IDEA_CBC_SHA',
        0x22: 'TLS_KRB5_WITH_DES_CBC_MD5',
        0x23: 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
        0x24: 'TLS_KRB5_WITH_RC4_128_MD5',
        0x25: 'TLS_KRB5_WITH_IDEA_CBC_MD5',
        0x26: 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',
        0x27: 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
        0x28: 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',
        0x29: 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',
        0x2A: 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
        0x2B: 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',
        0x2C: 'TLS_PSK_WITH_NULL_SHA',
        0x2D: 'TLS_DHE_PSK_WITH_NULL_SHA',
        0x2E: 'TLS_RSA_PSK_WITH_NULL_SHA',
        0x2F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
        0x30: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
        0x31: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
        0x32: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
        0x33: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
        0x34: 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
        0x35: 'TLS_RSA_WITH_AES_256_CBC_SHA',
        0x36: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
        0x37: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
        0x38: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
        0x39: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
        0x3A: 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
        0x3B: 'TLS_RSA_WITH_NULL_SHA256',
        0x3C: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
        0x3D: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
        0x3E: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
        0x3F: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
        0x40: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
        0x41: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
        0x42: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
        0x43: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
        0x44: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
        0x45: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
        0x46: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',
        0x60: 'TLS_RSA_EXPORT1024_WITH_RC4_56_MD5',
        0x61: 'TLS_RSA_EXPORT1024_WITH_RC2_56_MD5',
        0x62: 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA',
        0x63: 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
        0x64: 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA',
        0x65: 'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA',
        0x66: 'TLS_DHE_DSS_WITH_RC4_128_SHA',
        0x67: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
        0x68: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
        0x69: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
        0x6A: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
        0x6B: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
        0x6C: 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
        0x6D: 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
        0x80: 'TLS_GOSTR341094_WITH_28147_CNT_IMIT',
        0x81: 'TLS_GOSTR341001_WITH_28147_CNT_IMIT',
        0x82: 'TLS_GOSTR341094_WITH_NULL_GOSTR3411',
        0x83: 'TLS_GOSTR341001_WITH_NULL_GOSTR3411',
        0x84: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
        0x85: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
        0x86: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
        0x87: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
        0x88: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
        0x89: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',
        0x8A: 'TLS_PSK_WITH_RC4_128_SHA',
        0x8B: 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
        0x8C: 'TLS_PSK_WITH_AES_128_CBC_SHA',
        0x8D: 'TLS_PSK_WITH_AES_256_CBC_SHA',
        0x8E: 'TLS_DHE_PSK_WITH_RC4_128_SHA',
        0x8F: 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
        0x90: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
        0x91: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
        0x92: 'TLS_RSA_PSK_WITH_RC4_128_SHA',
        0x93: 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
        0x94: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
        0x95: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
        0x96: 'TLS_RSA_WITH_SEED_CBC_SHA',
        0x97: 'TLS_DH_DSS_WITH_SEED_CBC_SHA',
        0x98: 'TLS_DH_RSA_WITH_SEED_CBC_SHA',
        0x99: 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
        0x9A: 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
        0x9B: 'TLS_DH_anon_WITH_SEED_CBC_SHA',
        0x9C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
        0x9D: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
        0x9E: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
        0x9F: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
        0xA0: 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
        0xA1: 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
        0xA2: 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
        0xA3: 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
        0xA4: 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
        0xA5: 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
        0xA6: 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
        0xA7: 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
        0xA8: 'TLS_PSK_WITH_AES_128_GCM_SHA256',
        0xA9: 'TLS_PSK_WITH_AES_256_GCM_SHA384',
        0xAA: 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
        0xAB: 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
        0xAC: 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
        0xAD: 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
        0xAE: 'TLS_PSK_WITH_AES_128_CBC_SHA256',
        0xAF: 'TLS_PSK_WITH_AES_256_CBC_SHA384',
        0xB0: 'TLS_PSK_WITH_NULL_SHA256',
        0xB1: 'TLS_PSK_WITH_NULL_SHA384',
        0xB2: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
        0xB3: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
        0xB4: 'TLS_DHE_PSK_WITH_NULL_SHA256',
        0xB5: 'TLS_DHE_PSK_WITH_NULL_SHA384',
        0xB6: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
        0xB7: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
        0xB8: 'TLS_RSA_PSK_WITH_NULL_SHA256',
        0xB9: 'TLS_RSA_PSK_WITH_NULL_SHA384',
        0xBA: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256',
        0xBB: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
        0xBC: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
        0xBD: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
        0xBE: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
        0xBF: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
        0xC0: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256',
        0xC1: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
        0xC2: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
        0xC3: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
        0xC4: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
        0xC5: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256',
        0xFF: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
        0x5600: 'TLS_FALLBACK_SCSV',
        0xC001: 'TLS_ECDH_ECDSA_WITH_NULL_SHA',
        0xC002: 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
        0xC003: 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
        0xC004: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
        0xC005: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
        0xC006: 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
        0xC007: 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
        0xC008: 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
        0xC009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
        0xC00A: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        0xC00B: 'TLS_ECDH_RSA_WITH_NULL_SHA',
        0xC00C: 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
        0xC00D: 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
        0xC00E: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
        0xC00F: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
        0xC010: 'TLS_ECDHE_RSA_WITH_NULL_SHA',
        0xC011: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
        0xC012: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
        0xC013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        0xC014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        0xC015: 'TLS_ECDH_anon_WITH_NULL_SHA',
        0xC016: 'TLS_ECDH_anon_WITH_RC4_128_SHA',
        0xC017: 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
        0xC018: 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
        0xC019: 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
        0xC01A: 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',
        0xC01B: 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
        0xC01C: 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
        0xC01D: 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',
        0xC01E: 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
        0xC01F: 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
        0xC020: 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',
        0xC021: 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
        0xC022: 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
        0xC023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        0xC024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
        0xC025: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
        0xC026: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
        0xC027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        0xC028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        0xC029: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
        0xC02A: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
        0xC02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        0xC02C: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        0xC02D: 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
        0xC02E: 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
        0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        0xC031: 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
        0xC032: 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
        0xC033: 'TLS_ECDHE_PSK_WITH_RC4_128_SHA',
        0xC034: 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
        0xC035: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',
        0xC036: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',
        0xC037: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
        0xC038: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
        0xC039: 'TLS_ECDHE_PSK_WITH_NULL_SHA',
        0xC03A: 'TLS_ECDHE_PSK_WITH_NULL_SHA256',
        0xC03B: 'TLS_ECDHE_PSK_WITH_NULL_SHA384',
        0xC03C: 'TLS_RSA_WITH_ARIA_128_CBC_SHA256',
        0xC03D: 'TLS_RSA_WITH_ARIA_256_CBC_SHA384',
        0xC03E: 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256',
        0xC03F: 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384',
        0xC040: 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256',
        0xC041: 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384',
        0xC042: 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256',
        0xC043: 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384',
        0xC044: 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256',
        0xC045: 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384',
        0xC046: 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256',
        0xC047: 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384',
        0xC048: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256',
        0xC049: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384',
        0xC04A: 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256',
        0xC04B: 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384',
        0xC04C: 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256',
        0xC04D: 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384',
        0xC04E: 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256',
        0xC04F: 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384',
        0xC050: 'TLS_RSA_WITH_ARIA_128_GCM_SHA256',
        0xC051: 'TLS_RSA_WITH_ARIA_256_GCM_SHA384',
        0xC052: 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256',
        0xC053: 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384',
        0xC054: 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256',
        0xC055: 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384',
        0xC056: 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256',
        0xC057: 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384',
        0xC058: 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256',
        0xC059: 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384',
        0xC05A: 'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256',
        0xC05B: 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384',
        0xC05C: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
        0xC05D: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
        0xC05E: 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256',
        0xC05F: 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384',
        0xC060: 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
        0xC061: 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',
        0xC062: 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256',
        0xC063: 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384',
        0xC064: 'TLS_PSK_WITH_ARIA_128_CBC_SHA256',
        0xC065: 'TLS_PSK_WITH_ARIA_256_CBC_SHA384',
        0xC066: 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256',
        0xC067: 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384',
        0xC068: 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256',
        0xC069: 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384',
        0xC06A: 'TLS_PSK_WITH_ARIA_128_GCM_SHA256',
        0xC06B: 'TLS_PSK_WITH_ARIA_256_GCM_SHA384',
        0xC06C: 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256',
        0xC06D: 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384',
        0xC06E: 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256',
        0xC06F: 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384',
        0xC070: 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256',
        0xC071: 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384',
        0xC072: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
        0xC073: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
        0xC074: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
        0xC075: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
        0xC076: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
        0xC077: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
        0xC078: 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
        0xC079: 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
        0xC07A: 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256',
        0xC07B: 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384',
        0xC07C: 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
        0xC07D: 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
        0xC07E: 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
        0xC07F: 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
        0xC080: 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256',
        0xC081: 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384',
        0xC082: 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256',
        0xC083: 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384',
        0xC084: 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256',
        0xC085: 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384',
        0xC086: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
        0xC087: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
        0xC088: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
        0xC089: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
        0xC08A: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
        0xC08B: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
        0xC08C: 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
        0xC08D: 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
        0xC08E: 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256',
        0xC08F: 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384',
        0xC090: 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256',
        0xC091: 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384',
        0xC092: 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256',
        0xC093: 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384',
        0xC094: 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256',
        0xC095: 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384',
        0xC096: 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
        0xC097: 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
        0xC098: 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
        0xC099: 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
        0xC09A: 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
        0xC09B: 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
        0xC09C: 'TLS_RSA_WITH_AES_128_CCM',
        0xC09D: 'TLS_RSA_WITH_AES_256_CCM',
        0xC09E: 'TLS_DHE_RSA_WITH_AES_128_CCM',
        0xC09F: 'TLS_DHE_RSA_WITH_AES_256_CCM',
        0xC0A0: 'TLS_RSA_WITH_AES_128_CCM_8',
        0xC0A1: 'TLS_RSA_WITH_AES_256_CCM_8',
        0xC0A2: 'TLS_DHE_RSA_WITH_AES_128_CCM_8',
        0xC0A3: 'TLS_DHE_RSA_WITH_AES_256_CCM_8',
        0xC0A4: 'TLS_PSK_WITH_AES_128_CCM',
        0xC0A5: 'TLS_PSK_WITH_AES_256_CCM',
        0xC0A6: 'TLS_DHE_PSK_WITH_AES_128_CCM',
        0xC0A7: 'TLS_DHE_PSK_WITH_AES_256_CCM',
        0xC0A8: 'TLS_PSK_WITH_AES_128_CCM_8',
        0xC0A9: 'TLS_PSK_WITH_AES_256_CCM_8',
        0xC0AA: 'TLS_PSK_DHE_WITH_AES_128_CCM_8',
        0xC0AB: 'TLS_PSK_DHE_WITH_AES_256_CCM_8',
        0xC09C: 'TLS_RSA_WITH_AES_128_CCM',
        0xC09D: 'TLS_RSA_WITH_AES_256_CCM',
        0xC09E: 'TLS_DHE_RSA_WITH_AES_128_CCM',
        0xC09F: 'TLS_DHE_RSA_WITH_AES_256_CCM',
        0xC0A0: 'TLS_RSA_WITH_AES_128_CCM_8',
        0xC0A1: 'TLS_RSA_WITH_AES_256_CCM_8',
        0xC0A2: 'TLS_DHE_RSA_WITH_AES_128_CCM_8',
        0xC0A3: 'TLS_DHE_RSA_WITH_AES_256_CCM_8',
        0xC0A4: 'TLS_PSK_WITH_AES_128_CCM',
        0xC0A5: 'TLS_PSK_WITH_AES_256_CCM',
        0xC0A6: 'TLS_DHE_PSK_WITH_AES_128_CCM',
        0xC0A7: 'TLS_DHE_PSK_WITH_AES_256_CCM',
        0xC0A8: 'TLS_PSK_WITH_AES_128_CCM_8',
        0xC0A9: 'TLS_PSK_WITH_AES_256_CCM_8',
        0xC0AA: 'TLS_PSK_DHE_WITH_AES_128_CCM_8',
        0xC0AB: 'TLS_PSK_DHE_WITH_AES_256_CCM_80',
        0xC0AC: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
        0xC0AD: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM',
        0xC0AE: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8',
        0xC0AF: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8',
        0xCC13: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        0xCC14: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        0xCC15: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        0xCCA8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        0xCCA9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        0xFEFE: 'SSL_RSA_FIPS_WITH_DES_CBC_SHA',
        0xFEFE: 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',
        0xFFE0: 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',
        0xFFE1: 'SSL_RSA_FIPS_WITH_DES_CBC_SHA'
    },
    'compression_methods': {
        0: 'null',
        1: 'Zlib'
    },
    'ec_point_formats': {
        0: 'uncompressed',
        1: 'ansiX962_compressed_prime',
        2: 'ansiX962_compressed_char2'
    },
    'extension_type': {
        0: 'server_name',
        1: 'max_fragment_length',
        2: 'client_certificate_url',
        3: 'trusted_ca_keys',
        4: 'truncated_hmac',
        5: 'status_request',
        6: 'user_mapping',
        7: 'client_authz',
        8: 'server_authz',
        9: 'cert_type',
        10: 'elliptic_curves',
        11: 'ec_point_formats',
        12: 'srp',
        13: 'signature_algorithms',
        14: 'use_srtp',
        15: 'heartbeat',
        16: 'application_layer_protocol_negotiation',
        17: 'status_request_v2',
        18: 'signed_certificate_timestamp',
        19: 'client_certificate_type',
        20: 'server_certificate_type',
        21: 'padding',
        22: 'encrypt_then_mac',
        23: 'extended_master_secret',
        35: 'SessionTicket_TLS',
        13172: 'next_protocol_negotiation',
        30031: 'channel_id_old',
        30032: 'channel_id',
        62208: 'tack',
        65281: 'renegotiation_info'},
    'heartbeat': {
        0: 'heartbeat_request',
        1: 'peer_allowed_to_send'
    },
    'elliptic_curves': {
        1: 'sect163k1',
        2: 'sect163r1',
        3: 'sect163r2',
        4: 'sect193r1',
        5: 'sect193r2',
        6: 'sect233k1',
        7: 'sect233r1',
        8: 'sect239k1',
        9: 'sect283k1',
        10: 'sect283r1',
        11: 'sect409k1',
        12: 'sect409r1',
        13: 'sect571k1',
        14: 'sect571r1',
        15: 'secp160k1',
        16: 'secp160r1',
        17: 'secp160r2',
        18: 'secp192k1',
        19: 'secp192r1',
        20: 'secp224k1',
        21: 'secp224r1',
        22: 'secp256k1',
        23: 'secp256r1',
        24: 'secp384r1',
        25: 'secp521r1',
        26: 'brainpoolP256r1',
        27: 'brainpoolP384r1',
        28: 'brainpoolP512r1',
        256: 'ffdhe2048',
        257: 'ffdhe3072',
        258: 'ffdhe4096',
        259: 'ffdhe6144',
        260: 'ffdhe8192',
        65281: 'arbitrary_explicit_prime_curves',
        65282: 'arbitrary_explicit_char2_curves'
    },
    'signature_algorithms_hash': {  #RFC 5246
        0: 'none',
        1: 'md5',
        2: 'sha1',
        3: 'sha224',
        4: 'sha256',
        5: 'sha384',
        6: 'sha512'
    },
    'signature_algorithms_signature': {
        0: 'anonymous',
        1: 'rsa',
        2: 'dsa',
        3: 'ecdsa'
    },
    'status_request': {
        0: 'empty'
    },
    'tls_record': {
        20: 'change_cipher',
        21: 'alert',
        22: 'handshake',
        23: 'application_data'
    },
    'tls_version': {
        0x300: 'SSL 3.0',
        0x301: 'TLS 1.0',
        0x302: 'TLS 1.1',
        0x303: 'TLS 1.2',
    }
}