use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, SanType};

pub struct GeneratedCerts {
    pub ca_cert_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn generate_certs(
    hostname: &str,
    bind_ip: std::net::IpAddr,
    cert_names: &[String],
) -> anyhow::Result<GeneratedCerts> {
    // Certificate identity: explicit cert_names win, otherwise fall back to the
    // detected hostname. Each name is a DNS SAN unless it parses as an IP.
    let cn: String;
    let mut sans: Vec<SanType> = Vec::new();
    if cert_names.is_empty() {
        cn = hostname.to_string();
        sans.push(SanType::DnsName(hostname.try_into()?));
    } else {
        cn = cert_names[0].clone();
        for name in cert_names {
            if let Ok(ip) = name.parse::<std::net::IpAddr>() {
                sans.push(SanType::IpAddress(ip));
            } else {
                sans.push(SanType::DnsName(name.as_str().try_into()?));
            }
        }
    }
    // The bind IP MUST be a SAN: the iPhone connects to it, so the cert must
    // validate it. 127.0.0.1 stays as a local fail-safe.
    sans.push(SanType::IpAddress(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(127, 0, 0, 1),
    )));
    sans.push(SanType::IpAddress(bind_ip));

    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Clipperd CA");
        dn.push(DnType::OrganizationName, "Clipperd");
        dn
    };
    // Valid for 10 years
    ca_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2035, 1, 1);

    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_cert_pem = ca_cert.pem();

    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    // iOS 13+ rejects TLS certs with validity > 825 days — keep well under that.
    let now = time::OffsetDateTime::now_utc();
    let two_years = now + time::Duration::days(730);

    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::default();
    server_params.is_ca = rcgen::IsCa::NoCa;
    server_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn.as_str());
        dn
    };
    server_params.not_before = now;
    server_params.not_after = two_years;
    server_params.subject_alt_names = sans;

    let server_cert = server_params.signed_by(&server_key, &ca_issuer)?;

    Ok(GeneratedCerts {
        ca_cert_pem,
        cert_pem: server_cert.pem(),
        key_pem: server_key.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn test_ip() -> IpAddr {
        "192.168.1.100".parse().unwrap()
    }

    #[test]
    fn generate_certs_produces_valid_pem() {
        let certs = generate_certs("test-host", test_ip(), &[]).unwrap();
        assert!(certs.ca_cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(certs.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(certs.key_pem.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn fingerprint_is_formatted_correctly() {
        let certs = generate_certs("test-host", test_ip(), &[]).unwrap();
        let fp = cert_fingerprint(&certs.ca_cert_pem).unwrap();
        // Expected: 16 uppercase hex byte pairs separated by colons → "AA:BB:...:FF"
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 16, "fingerprint should have 16 byte pairs");
        for part in &parts {
            assert_eq!(part.len(), 2, "each part should be 2 hex chars");
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()), "must be hex");
            assert_eq!(*part, part.to_uppercase(), "must be uppercase");
        }
    }

    #[test]
    fn fingerprint_is_deterministic_for_same_cert() {
        let certs = generate_certs("test-host", test_ip(), &[]).unwrap();
        let fp1 = cert_fingerprint(&certs.ca_cert_pem).unwrap();
        let fp2 = cert_fingerprint(&certs.ca_cert_pem).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn different_certs_have_different_fingerprints() {
        let a = generate_certs("host-a", test_ip(), &[]).unwrap();
        let b = generate_certs("host-b", test_ip(), &[]).unwrap();
        // Different CA keys → different fingerprints
        assert_ne!(
            cert_fingerprint(&a.ca_cert_pem).unwrap(),
            cert_fingerprint(&b.ca_cert_pem).unwrap()
        );
    }

    /// The PEM is base64 DER, so the CN is only visible as plain bytes after
    /// decoding. Return the decoded DER.
    fn decode_pem(pem: &str) -> Vec<u8> {
        use base64::Engine as _;
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("---"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64")
    }

    #[test]
    fn cert_names_override_hostname_in_cn() {
        let certs = generate_certs("auto-host", test_ip(), &["mybox.lan".to_string()]).unwrap();
        let der = decode_pem(&certs.cert_pem);
        assert!(String::from_utf8_lossy(&der).contains("mybox.lan"));
        // The auto hostname should not appear when overridden.
        assert!(!String::from_utf8_lossy(&der).contains("auto-host"));
    }

    #[test]
    fn no_cert_names_uses_hostname() {
        let certs = generate_certs("auto-host", test_ip(), &[]).unwrap();
        let der = decode_pem(&certs.cert_pem);
        assert!(String::from_utf8_lossy(&der).contains("auto-host"));
    }

    #[test]
    fn multiple_cert_names_all_appear_in_cert() {
        let names = vec!["a.lan".to_string(), "b.lan".to_string()];
        let certs = generate_certs("auto-host", test_ip(), &names).unwrap();
        let der = String::from_utf8_lossy(&decode_pem(&certs.cert_pem)).into_owned();
        assert!(der.contains("a.lan"));
        assert!(der.contains("b.lan"));
    }

    #[test]
    fn bind_ip_stays_in_cert_alongside_cert_names() {
        // Even when cert_names are given, the bind_ip must still appear as an
        // IP SAN (the iPhone connects to the bind IP, so the cert must cover it).
        let names = vec!["a.lan".to_string(), "b.lan".to_string()];
        let certs = generate_certs("auto-host", test_ip(), &names).unwrap();
        let der = decode_pem(&certs.cert_pem);
        // 192.168.1.100 as big-endian octets in the DER.
        assert!(der.windows(4).any(|w| w == [0xc0, 0xa8, 0x01, 0x64]));
    }

    #[test]
    fn fingerprint_rejects_empty_input() {
        assert!(cert_fingerprint("").is_err());
        assert!(cert_fingerprint("not a pem").is_err());
    }
}

pub fn cert_fingerprint(ca_cert_pem: &str) -> anyhow::Result<String> {
    use rustls_pemfile::certs;
    let mut reader = std::io::BufReader::new(ca_cert_pem.as_bytes());
    let der_certs: Vec<_> = certs(&mut reader).collect::<Result<_, _>>()?;
    let der = der_certs.first().ok_or_else(|| anyhow::anyhow!("No cert found"))?;
    let hash = blake3::hash(der.as_ref());
    let hex = hex::encode(&hash.as_bytes()[..16]);
    let formatted: String = hex.as_bytes().chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":");
    Ok(formatted.to_uppercase())
}
