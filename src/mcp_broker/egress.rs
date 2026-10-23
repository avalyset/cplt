//! The child's own CONNECT proxy, allowing only its `egressHosts`.

use std::io::{BufReader, Write};
use std::time::Duration;

use super::runtime::{Log, read_line};

/// The egress decision for a CONNECT target: port 443 only, host equal to
/// or a subdomain of an `egressHosts` entry. Returns the host to dial.
pub fn egress_allowed(target: &str, hosts: &[String]) -> Result<String, String> {
    let (host, port) = target.rsplit_once(':').ok_or("no port")?;
    if port != "443" {
        return Err(format!("port {port}"));
    }
    let host = crate::proxy::normalize_hostname(host);
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err("not a hostname".into());
    }
    if hosts
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
    {
        Ok(host)
    } else {
        Err(format!("{host} is not in egressHosts"))
    }
}

/// A public address: the child must not be steered at loopback or the LAN
/// through a name it is allowed.
pub(crate) fn public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            !(v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.octets()[0] == 100 && v.octets()[1] & 0xc0 == 64)
        }
        std::net::IpAddr::V6(v) => {
            let s = v.segments()[0];
            !(v.is_loopback() || v.is_unspecified() || s & 0xfe00 == 0xfc00 || s & 0xffc0 == 0xfe80)
                && v.to_ipv4_mapped().is_none_or(|m| public_ip(m.into()))
        }
    }
}

/// One child connection to its egress proxy: a CONNECT head, the policy
/// check, then bytes both ways. Anything else gets 403.
pub(crate) fn egress_tunnel(client: std::net::TcpStream, hosts: &[String], log: &Log, id: &str) {
    use std::net::{TcpStream, ToSocketAddrs};
    let _ = client.set_nonblocking(false);
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(read_half) = client.try_clone() else {
        return;
    };
    let mut r = BufReader::new(read_half);
    let Some(first) = read_line(&mut r, 2048) else {
        return;
    };
    // Skip the rest of the head.
    loop {
        match read_line(&mut r, 8192) {
            Some(l) if l.is_empty() => break,
            Some(_) => {}
            None => return,
        }
    }
    let mut w = &client;
    let mut parts = first.split(' ');
    let decision = match (parts.next(), parts.next()) {
        (Some("CONNECT"), Some(target)) => egress_allowed(target, hosts),
        _ => Err("only CONNECT is proxied".into()),
    };
    let upstream = decision.and_then(|host| {
        let addrs: Vec<_> = (host.as_str(), 443)
            .to_socket_addrs()
            .map_err(|e| format!("{host}: {e}"))?
            .filter(|a| public_ip(a.ip()))
            .collect();
        let mut last = String::from("no public address");
        for a in &addrs {
            match TcpStream::connect_timeout(a, Duration::from_secs(10)) {
                Ok(s) => return Ok(s),
                Err(e) => last = format!("{a}: {e}"),
            }
        }
        Err(format!("CONNECT-FAIL {host} ({last})"))
    });
    let upstream = match upstream {
        Ok(u) => u,
        Err(why) => {
            log.line(id, &format!("egress → DENIED {why}"));
            let _ = w.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };
    if w.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let _ = client.set_read_timeout(None);
    let (Ok(mut up_w), Ok(mut down_w)) = (upstream.try_clone(), client.try_clone()) else {
        return;
    };
    // Bytes the head reader buffered past the blank line go first.
    let buffered = r.buffer().to_vec();
    let mut r = r.into_inner();
    let up = std::thread::spawn(move || {
        if up_w.write_all(&buffered).is_ok() {
            let _ = std::io::copy(&mut r, &mut up_w);
        }
        let _ = up_w.shutdown(std::net::Shutdown::Write);
    });
    let mut upstream = upstream;
    let _ = std::io::copy(&mut upstream, &mut down_w);
    let _ = down_w.shutdown(std::net::Shutdown::Both);
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_policy() {
        let hosts = vec!["console.nav.cloud.nais.io".to_string()];
        assert!(egress_allowed("console.nav.cloud.nais.io:443", &hosts).is_ok());
        assert!(egress_allowed("x.console.nav.cloud.nais.io:443", &hosts).is_ok());
        assert!(egress_allowed("console.nav.cloud.nais.io:80", &hosts).is_err());
        assert!(egress_allowed("evilconsole.nav.cloud.nais.io:443", &hosts).is_err());
        assert!(egress_allowed("example.com:443", &hosts).is_err());
        assert!(!public_ip("127.0.0.1".parse().unwrap()));
        assert!(!public_ip("10.1.2.3".parse().unwrap()));
        assert!(!public_ip("::ffff:192.168.0.1".parse().unwrap()));
        assert!(public_ip("1.1.1.1".parse().unwrap()));
    }
}
