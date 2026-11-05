//! What a `--base-url` is: the production guard and the loopback test behind the load-only
//! identity rule (see [`crate::identity::for_base_url`]).

use anyhow::{anyhow, bail, Context, Result};

/// Refuse the production host unless asked, and any URL that does not parse.
pub fn check_base_url(raw: &str, allow_production: bool) -> Result<String> {
    let url = reqwest::Url::parse(raw).with_context(|| format!("--base-url {raw:?}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("--base-url must be http or https, got {raw:?}");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("--base-url {raw:?} has no host"))?
        .to_ascii_lowercase();
    let production = host == "openwitness.org" || host.ends_with(".openwitness.org");
    if production && !allow_production {
        bail!("{host} is production: refusing without --allow-production");
    }
    Ok(raw.trim_end_matches('/').to_string())
}

/// True only for a URL that names this machine: `localhost`, or a loopback IP literal. Anything
/// else, and anything that does not parse, is a remote: the safe answer for the identity rule.
pub fn is_loopback(base_url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(base_url) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_host_needs_the_flag() {
        for url in [
            "https://openwitness.org",
            "https://openwitness.org/",
            "https://OpenWitness.org:443/x",
            "https://api.openwitness.org",
        ] {
            assert!(check_base_url(url, false).is_err(), "{url}");
            assert!(check_base_url(url, true).is_ok(), "{url}");
        }
    }

    #[test]
    fn other_hosts_pass_and_are_normalised() {
        assert_eq!(
            check_base_url("http://127.0.0.1:8080/", false).unwrap(),
            "http://127.0.0.1:8080"
        );
        assert!(check_base_url("https://staging.example.org", false).is_ok());
        assert!(check_base_url("https://notopenwitness.org", false).is_ok());
    }

    #[test]
    fn junk_urls_are_refused() {
        assert!(check_base_url("openwitness.org", true).is_err());
        assert!(check_base_url("ftp://example.org", false).is_err());
    }

    #[test]
    fn loopback_is_this_machine_and_nothing_else() {
        for url in [
            "http://127.0.0.1:8080",
            "http://127.1.2.3",
            "http://localhost:1",
            "http://LOCALHOST",
            "http://[::1]:8080",
        ] {
            assert!(is_loopback(url), "{url}");
        }
        for url in [
            "https://openwitness.org",
            "https://127.0.0.1.example.org",
            "https://localhost.example.org",
            "http://0.0.0.0:1",
            "http://192.168.1.1",
            "http://[::ffff:127.0.0.1]",
            "not a url",
            "",
        ] {
            assert!(!is_loopback(url), "{url}");
        }
    }
}
