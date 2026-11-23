//! iptables/ip6tables rules that force sandbox egress through the
//! transparent proxy (strict / L3 mode). Rule construction is portable and
//! unit-tested; executing it is Linux-only.

use std::io;
use std::net::IpAddr;

/// The resolvers DNS (port 53, UDP and TCP) may reach, as a comma-separated
/// list of IPs. DNS to any other destination is dropped. Unset, the
/// nameservers in [`RESOLV_CONF`] are used; with neither, setup fails.
pub const DNS_RESOLVERS_ENV: &str = "RUNEBOX_DNS_RESOLVERS";

/// Where the Citadel's own resolvers are read from when
/// [`DNS_RESOLVERS_ENV`] is unset. The setup runs in the Citadel's network
/// namespace (the Docker sidecar the sandbox joins, or the Pod's init
/// container), whose resolv.conf is the one the sandbox uses.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// nat-table chain redirecting outbound TCP to the proxy.
pub const CHAIN: &str = "RUNEBOX_OUT";
/// filter-table chain dropping non-DNS UDP.
pub const UDP_CHAIN: &str = "RUNEBOX_UDP";
/// filter-table chain confining TCP DNS to the resolvers.
pub const DNS_TCP_CHAIN: &str = "RUNEBOX_DNST";
/// ip6tables chain dropping IPv6 egress.
pub const CHAIN6: &str = "RUNEBOX_OUT6";

/// Returns the valid resolver IPs from a `RUNEBOX_DNS_RESOLVERS` value
/// (garbage entries are skipped; [`resolvers`] refuses a list left empty).
pub fn parse_dns_resolvers(raw: &str) -> Vec<IpAddr> {
    raw.trim()
        .split(',')
        .map(str::trim)
        .filter_map(|f| f.parse().ok())
        .collect()
}

/// Returns the `nameserver` addresses of a resolv.conf (entries that are not
/// a plain IP, such as a link-local address with a zone, are skipped).
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            (f.next() == Some("nameserver"))
                .then(|| f.next())
                .flatten()
                .and_then(|ip| ip.parse().ok())
        })
        .collect()
}

/// Picks the resolvers DNS is confined to: the `RUNEBOX_DNS_RESOLVERS`
/// value when set, else the nameservers of the Citadel's resolv.conf (`None`
/// when it cannot be read). Fails when neither names a resolver, so strict
/// egress never leaves port 53 open to every address.
pub fn resolvers(env: Option<&str>, resolv_conf: Option<&str>) -> io::Result<Vec<IpAddr>> {
    if let Some(raw) = env.filter(|r| !r.trim().is_empty()) {
        let ips = parse_dns_resolvers(raw);
        if ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{DNS_RESOLVERS_ENV}={raw:?} names no valid resolver IP"),
            ));
        }
        return Ok(ips);
    }
    let ips = resolv_conf.map(parse_resolv_conf).unwrap_or_default();
    if ips.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "no DNS resolver known: {RESOLV_CONF} lists no nameserver and {DNS_RESOLVERS_ENV} is unset; strict egress needs one to confine port 53 to"
            ),
        ));
    }
    Ok(ips)
}

/// Splits resolvers into the IPv4 and IPv6 addresses, as strings for
/// iptables and ip6tables.
fn by_family(resolvers: &[IpAddr]) -> (Vec<String>, Vec<String>) {
    let (v4, v6): (Vec<_>, Vec<_>) = resolvers.iter().partition(|ip| ip.is_ipv4());
    let s = |ips: Vec<&IpAddr>| ips.iter().map(ToString::to_string).collect();
    (s(v4), s(v6))
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_string()).collect()
}

/// Best-effort deletions run before setup so re-runs don't stack rules.
pub fn flush_steps() -> Vec<Vec<String>> {
    vec![
        args(&["-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", CHAIN]),
        args(&["-t", "nat", "-F", CHAIN]),
        args(&["-t", "nat", "-X", CHAIN]),
        args(&["-t", "filter", "-D", "OUTPUT", "-p", "udp", "-j", UDP_CHAIN]),
        args(&["-t", "filter", "-F", UDP_CHAIN]),
        args(&["-t", "filter", "-X", UDP_CHAIN]),
        args(&[
            "-t",
            "filter",
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "53",
            "-j",
            DNS_TCP_CHAIN,
        ]),
        args(&["-t", "filter", "-F", DNS_TCP_CHAIN]),
        args(&["-t", "filter", "-X", DNS_TCP_CHAIN]),
    ]
}

/// The IPv4 rules (in order) that redirect outbound TCP to `redirect_port`,
/// exempting `proxy_uid`, loopback and DNS; drop non-DNS UDP (QUIC/HTTP3
/// bypass); and confine UDP and TCP DNS to the IPv4 `resolvers`. With none,
/// all DNS off loopback is dropped.
pub fn redirect_steps(
    proxy_uid: u32,
    redirect_port: u16,
    resolvers: &[String],
) -> Vec<Vec<String>> {
    let uid = proxy_uid.to_string();
    let port = redirect_port.to_string();
    let uid = uid.as_str();

    let mut steps = vec![
        args(&["-t", "nat", "-N", CHAIN]),
        // Don't redirect the proxy's own egress back to itself.
        args(&[
            "-t",
            "nat",
            "-A",
            CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            uid,
            "-j",
            "RETURN",
        ]),
        args(&["-t", "nat", "-A", CHAIN, "-o", "lo", "-j", "RETURN"]),
        // Let DNS through (not redirected) so name resolution keeps working.
        // This RETURN must stay paired with the filter-table chains below,
        // which drop :53 to anything but the resolvers; without them it
        // would be an open TCP path to any host listening on port 53.
        args(&[
            "-t", "nat", "-A", CHAIN, "-p", "udp", "--dport", "53", "-j", "RETURN",
        ]),
        args(&[
            "-t", "nat", "-A", CHAIN, "-p", "tcp", "--dport", "53", "-j", "RETURN",
        ]),
        args(&[
            "-t",
            "nat",
            "-A",
            CHAIN,
            "-p",
            "tcp",
            "-j",
            "REDIRECT",
            "--to-ports",
            &port,
        ]),
        args(&["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", CHAIN]),
        // Drop non-DNS UDP (QUIC/HTTP3 bypass) via a filter-table chain.
        args(&["-t", "filter", "-N", UDP_CHAIN]),
        args(&[
            "-t",
            "filter",
            "-A",
            UDP_CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            uid,
            "-j",
            "RETURN",
        ]),
        args(&["-t", "filter", "-A", UDP_CHAIN, "-o", "lo", "-j", "RETURN"]),
    ];
    // UDP DNS reaches only the resolvers; everything else falls through to
    // the DROP.
    for ip in resolvers {
        steps.push(args(&[
            "-t", "filter", "-A", UDP_CHAIN, "-p", "udp", "-d", ip, "--dport", "53", "-j", "RETURN",
        ]));
    }
    steps.push(args(&[
        "-t", "filter", "-A", UDP_CHAIN, "-p", "udp", "-j", "DROP",
    ]));
    steps.push(args(&[
        "-t", "filter", "-A", "OUTPUT", "-p", "udp", "-j", UDP_CHAIN,
    ]));

    // TCP DNS (large responses) is confined the same way, so the nat RETURN
    // above cannot carry a connection to anything but a resolver.
    steps.push(args(&["-t", "filter", "-N", DNS_TCP_CHAIN]));
    steps.push(args(&[
        "-t",
        "filter",
        "-A",
        DNS_TCP_CHAIN,
        "-m",
        "owner",
        "--uid-owner",
        uid,
        "-j",
        "RETURN",
    ]));
    steps.push(args(&[
        "-t",
        "filter",
        "-A",
        DNS_TCP_CHAIN,
        "-o",
        "lo",
        "-j",
        "RETURN",
    ]));
    for ip in resolvers {
        steps.push(args(&[
            "-t",
            "filter",
            "-A",
            DNS_TCP_CHAIN,
            "-p",
            "tcp",
            "-d",
            ip,
            "--dport",
            "53",
            "-j",
            "RETURN",
        ]));
    }
    steps.push(args(&[
        "-t",
        "filter",
        "-A",
        DNS_TCP_CHAIN,
        "-p",
        "tcp",
        "--dport",
        "53",
        "-j",
        "DROP",
    ]));
    steps.push(args(&[
        "-t",
        "filter",
        "-A",
        "OUTPUT",
        "-p",
        "tcp",
        "--dport",
        "53",
        "-j",
        DNS_TCP_CHAIN,
    ]));
    steps
}

/// Best-effort deletions of a prior IPv6 chain.
pub fn ipv6_flush_steps() -> Vec<Vec<String>> {
    vec![
        args(&["-D", "OUTPUT", "-j", CHAIN6]),
        args(&["-F", CHAIN6]),
        args(&["-X", CHAIN6]),
    ]
}

/// ip6tables rules dropping all IPv6 egress except loopback and DNS to the
/// IPv6 `resolvers` (the proxy is IPv4-only, so this forces traffic onto
/// the proxied path).
pub fn ipv6_drop_steps(resolvers: &[String]) -> Vec<Vec<String>> {
    let mut steps = vec![
        args(&["-N", CHAIN6]),
        args(&["-A", CHAIN6, "-o", "lo", "-j", "RETURN"]),
    ];
    for ip in resolvers {
        for proto in ["udp", "tcp"] {
            steps.push(args(&[
                "-A", CHAIN6, "-p", proto, "-d", ip, "--dport", "53", "-j", "RETURN",
            ]));
        }
    }
    steps.push(args(&["-A", CHAIN6, "-j", "DROP"]));
    steps.push(args(&["-A", "OUTPUT", "-j", CHAIN6]));
    steps
}

/// Runs the full setup sequence through `run(program, args)`: best-effort
/// flush, fail-fast IPv4 steps, then best-effort IPv6 drop. Refuses an
/// empty resolver list before touching anything.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn setup_redirect_with<F>(
    mut run: F,
    proxy_uid: u32,
    redirect_port: u16,
    resolvers: &[IpAddr],
) -> io::Result<()>
where
    F: FnMut(&str, &[String]) -> io::Result<()>,
{
    if resolvers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no DNS resolver to confine port 53 to",
        ));
    }
    let (resolvers4, resolvers6) = by_family(resolvers);
    let (v4, v6) = pick_backend(&mut run);
    for a in flush_steps() {
        let _ = run(v4, &a);
    }
    for a in redirect_steps(proxy_uid, redirect_port, &resolvers4) {
        run(v4, &a).map_err(|e| {
            // gVisor has no nftables, and its legacy nat table exists only
            // with runsc's net-raw option.
            let hint = if e.to_string().contains("nft") {
                " (under gVisor, set net-raw = \"true\" in runsc's configuration)"
            } else {
                ""
            };
            io::Error::new(e.kind(), format!("{v4} {}: {e}{hint}", a.join(" ")))
        })?;
    }
    // Some environments lack IPv6/ip6tables entirely, which is fine (nothing
    // to bypass through), so failures here are ignored.
    for a in ipv6_flush_steps()
        .into_iter()
        .chain(ipv6_drop_steps(&resolvers6))
    {
        let _ = run(v6, &a);
    }
    Ok(())
}

/// The iptables programs to use: the default (nftables) ones, or the legacy
/// ones when only those can read the nat table. gVisor implements the legacy
/// interface only.
fn pick_backend<F>(run: &mut F) -> (&'static str, &'static str)
where
    F: FnMut(&str, &[String]) -> io::Result<()>,
{
    let probe = args(&["-t", "nat", "-S"]);
    if run("iptables", &probe).is_err() && run("iptables-legacy", &probe).is_ok() {
        ("iptables-legacy", "ip6tables-legacy")
    } else {
        ("iptables", "ip6tables")
    }
}

/// Installs the iptables rules redirecting outbound TCP to the transparent
/// proxy on `redirect_port`, exempting `proxy_uid`, loopback and DNS to the
/// resolvers, and closing the UDP/QUIC and IPv6 bypasses. The resolvers come
/// from [`DNS_RESOLVERS_ENV`], else [`RESOLV_CONF`]; with neither it fails.
/// Runs once, privileged, before the sandbox starts.
#[cfg(target_os = "linux")]
pub fn setup_redirect(proxy_uid: u32, redirect_port: u16) -> io::Result<()> {
    let env = std::env::var(DNS_RESOLVERS_ENV).ok();
    let conf = std::fs::read_to_string(RESOLV_CONF).ok();
    let resolvers = resolvers(env.as_deref(), conf.as_deref())?;
    setup_redirect_with(run_command, proxy_uid, redirect_port, &resolvers)
}

/// Unsupported off Linux.
#[cfg(not(target_os = "linux"))]
pub fn setup_redirect(_proxy_uid: u32, _redirect_port: u16) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "iptables egress redirect is only supported on linux",
    ))
}

#[cfg(target_os = "linux")]
fn run_command(program: &str, args: &[String]) -> io::Result<()> {
    let out = std::process::Command::new(program).args(args).output()?;
    if out.status.success() {
        return Ok(());
    }
    let mut combined = out.stdout;
    combined.extend_from_slice(&out.stderr);
    Err(io::Error::other(format!(
        "{}: {}",
        out.status,
        String::from_utf8_lossy(&combined).trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().expect("ip")).collect()
    }

    #[test]
    fn parse_resolvers_skips_garbage() {
        assert!(parse_dns_resolvers("").is_empty());
        assert_eq!(
            parse_dns_resolvers(" 1.1.1.1, nope ,,2606:4700::1111 "),
            ips(&["1.1.1.1", "2606:4700::1111"])
        );
    }

    #[test]
    fn resolv_conf_nameservers() {
        let conf = "# generated\nsearch svc.cluster.local\nnameserver 10.96.0.10\nnameserver  fe80::1%eth0\nnameserver 2001:db8::53\noptions ndots:5\nnameserver\n";
        assert_eq!(
            parse_resolv_conf(conf),
            ips(&["10.96.0.10", "2001:db8::53"])
        );
        assert!(parse_resolv_conf("search x\n").is_empty());
    }

    #[test]
    fn resolvers_prefer_the_env_then_the_citadels_resolv_conf() {
        let conf = Some("nameserver 127.0.0.11\n");
        assert_eq!(
            resolvers(Some("9.9.9.9"), conf).expect("env"),
            ips(&["9.9.9.9"])
        );
        // Unset or blank: the Citadel's own resolver.
        assert_eq!(resolvers(None, conf).expect("conf"), ips(&["127.0.0.11"]));
        assert_eq!(
            resolvers(Some("  "), conf).expect("conf"),
            ips(&["127.0.0.11"])
        );
        // A set value with no valid IP is an error, never "any resolver".
        let err = resolvers(Some("nope,"), conf).expect_err("garbage");
        assert!(err.to_string().contains(DNS_RESOLVERS_ENV), "{err}");
        // No resolver known at all: strict egress is refused.
        for conf in [None, Some(""), Some("search x\n")] {
            let err = resolvers(None, conf).expect_err("no resolver");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("no DNS resolver"), "{err}");
        }
    }

    fn joined(steps: &[Vec<String>]) -> Vec<String> {
        steps.iter().map(|s| s.join(" ")).collect()
    }

    /// The filter-table fate of an IPv4 packet: walks OUTPUT and the chain
    /// it jumps to, as iptables would, for a non-proxy, non-loopback packet.
    fn filter_verdict(steps: &[String], proto: &str, dst: &str, dport: u16) -> &'static str {
        let matches = |rule: &str| {
            let f: Vec<&str> = rule.split_whitespace().collect();
            let opt = |k: &str| f.iter().position(|x| *x == k).map(|i| f[i + 1]);
            if opt("-m") == Some("owner") || opt("-o") == Some("lo") {
                return false;
            }
            opt("-p").is_none_or(|p| p == proto)
                && opt("-d").is_none_or(|d| d == dst)
                && opt("--dport").is_none_or(|p| p == dport.to_string())
        };
        let filter: Vec<&String> = steps
            .iter()
            .filter(|l| l.starts_with("-t filter -A "))
            .collect();
        for out in filter.iter().filter(|l| l.contains(" -A OUTPUT ")) {
            if !matches(out) {
                continue;
            }
            let chain = out.rsplit(' ').next().expect("target");
            for r in filter
                .iter()
                .filter(|l| l.starts_with(&format!("-t filter -A {chain} ")))
            {
                if matches(r) {
                    if r.ends_with("-j DROP") {
                        return "DROP";
                    }
                    if r.ends_with("-j RETURN") {
                        break;
                    }
                }
            }
        }
        "ACCEPT"
    }

    #[test]
    fn dns_to_anything_but_the_resolvers_is_dropped() {
        let r = vec!["10.0.0.2".to_string()];
        let s = joined(&redirect_steps(1337, 15001, &r));
        for proto in ["udp", "tcp"] {
            assert_eq!(
                filter_verdict(&s, proto, "10.0.0.2", 53),
                "ACCEPT",
                "{proto}"
            );
            assert_eq!(
                filter_verdict(&s, proto, "203.0.113.9", 53),
                "DROP",
                "{proto}"
            );
        }
        // Other UDP is dropped; other TCP is left to the nat redirect.
        assert_eq!(filter_verdict(&s, "udp", "203.0.113.9", 443), "DROP");
        assert_eq!(filter_verdict(&s, "tcp", "203.0.113.9", 443), "ACCEPT");
        // No filter rule lets :53 through without naming a resolver.
        assert!(
            !s.iter().any(|l| l.starts_with("-t filter")
                && l.contains("--dport 53 -j RETURN")
                && !l.contains(" -d ")),
            "{s:#?}"
        );
    }

    #[test]
    fn steps_without_ipv4_resolvers_drop_all_dns() {
        let s = joined(&redirect_steps(1337, 15001, &[]));
        assert_eq!(s[0], "-t nat -N RUNEBOX_OUT");
        assert!(
            s.contains(&"-t nat -A RUNEBOX_OUT -m owner --uid-owner 1337 -j RETURN".to_string())
        );
        assert!(
            s.contains(&"-t nat -A RUNEBOX_OUT -p tcp -j REDIRECT --to-ports 15001".to_string())
        );
        for proto in ["udp", "tcp"] {
            assert_eq!(filter_verdict(&s, proto, "1.1.1.1", 53), "DROP", "{proto}");
        }
        assert_eq!(
            s.last().map(String::as_str),
            Some("-t filter -A OUTPUT -p tcp --dport 53 -j RUNEBOX_DNST")
        );
        assert_eq!(s.len(), 17);
    }

    #[test]
    fn steps_with_resolvers() {
        let r = vec!["10.0.0.2".to_string(), "10.0.0.3".to_string()];
        let s = joined(&redirect_steps(7, 9, &r));
        assert!(!s.contains(&"-t filter -A RUNEBOX_UDP -p udp --dport 53 -j RETURN".to_string()));
        assert!(s.contains(
            &"-t filter -A RUNEBOX_UDP -p udp -d 10.0.0.3 --dport 53 -j RETURN".to_string()
        ));
        assert!(s.contains(&"-t filter -N RUNEBOX_DNST".to_string()));
        assert!(s.contains(
            &"-t filter -A RUNEBOX_DNST -p tcp -d 10.0.0.2 --dport 53 -j RETURN".to_string()
        ));
        assert_eq!(
            s.last().map(String::as_str),
            Some("-t filter -A OUTPUT -p tcp --dport 53 -j RUNEBOX_DNST")
        );
        assert_eq!(s.len(), 21);
        let drop_udp = s
            .iter()
            .position(|l| l == "-t filter -A RUNEBOX_UDP -p udp -j DROP");
        let allow_udp = s
            .iter()
            .position(|l| l.contains("RUNEBOX_UDP -p udp -d 10.0.0.3"));
        assert!(allow_udp < drop_udp);
    }

    #[test]
    fn setup_sequence_is_best_effort_where_go_is() {
        let mut calls = Vec::new();
        let res = setup_redirect_with(
            |prog, a| {
                calls.push(format!("{prog} {}", a.join(" ")));
                // Flushes and ip6tables fail; real steps succeed.
                if prog == "ip6tables" || a.iter().any(|x| x == "-D" || x == "-F" || x == "-X") {
                    Err(io::Error::other("nope"))
                } else {
                    Ok(())
                }
            },
            1337,
            15001,
            &ips(&["10.0.0.2", "2001:db8::53"]),
        );
        assert!(res.is_ok());
        // Probe, flushes, 19 IPv4 steps, 3 IPv6 flushes and 6 IPv6 steps.
        assert_eq!(calls.len(), 1 + flush_steps().len() + 19 + 3 + 6);
        assert!(calls.contains(
            &"ip6tables -A RUNEBOX_OUT6 -p tcp -d 2001:db8::53 --dport 53 -j RETURN".to_string()
        ));
        assert!(
            !calls
                .iter()
                .any(|c| c.starts_with("iptables ") && c.contains("2001:db8::53")),
            "an IPv6 resolver never reaches iptables"
        );
        assert!(
            calls
                .last()
                .is_some_and(|c| c == "ip6tables -A OUTPUT -j RUNEBOX_OUT6")
        );
    }

    #[test]
    fn setup_stops_on_first_failing_step() {
        let mut n = 0;
        let err = setup_redirect_with(
            |_, a| {
                n += 1;
                if a.join(" ") == "-t nat -A OUTPUT -p tcp -j RUNEBOX_OUT" {
                    Err(io::Error::other("boom"))
                } else {
                    Ok(())
                }
            },
            1,
            2,
            &ips(&["10.0.0.2"]),
        )
        .expect_err("must fail");
        assert!(
            err.to_string()
                .contains("iptables -t nat -A OUTPUT -p tcp -j RUNEBOX_OUT: boom")
        );
        assert_eq!(n, 1 + flush_steps().len() + 7);
    }

    #[test]
    fn falls_back_to_legacy_iptables_without_nftables() {
        let mut calls = Vec::new();
        setup_redirect_with(
            |prog, a| {
                calls.push(format!("{prog} {}", a.join(" ")));
                if prog == "iptables" || prog == "ip6tables" {
                    Err(io::Error::other(
                        "Failed to initialize nft: Protocol not supported",
                    ))
                } else {
                    Ok(())
                }
            },
            1337,
            15001,
            &ips(&["10.0.0.2"]),
        )
        .expect("legacy backend");
        assert_eq!(calls[0], "iptables -t nat -S");
        assert_eq!(calls[1], "iptables-legacy -t nat -S");
        assert!(
            calls[2..]
                .iter()
                .all(|c| c.starts_with("iptables-legacy ") || c.starts_with("ip6tables-legacy "))
        );
        assert!(
            calls
                .iter()
                .any(|c| c == "iptables-legacy -t nat -A OUTPUT -p tcp -j RUNEBOX_OUT")
        );
    }

    #[test]
    fn keeps_nftables_when_neither_backend_answers() {
        let mut progs = Vec::new();
        let err = setup_redirect_with(
            |prog, _| {
                progs.push(prog.to_owned());
                Err(io::Error::other("no"))
            },
            1,
            2,
            &ips(&["10.0.0.2"]),
        )
        .expect_err("must fail");
        assert_eq!(progs[..2], ["iptables", "iptables-legacy"]);
        assert!(progs[2..].iter().all(|p| p == "iptables"), "{progs:?}");
        assert!(err.to_string().starts_with("iptables "), "{err}");
        assert!(!err.to_string().contains("gVisor"), "{err}");
    }

    #[test]
    fn setup_without_resolvers_is_refused_before_any_rule() {
        let mut calls = 0;
        let err = setup_redirect_with(
            |_, _| {
                calls += 1;
                Ok(())
            },
            1337,
            15001,
            &[],
        )
        .expect_err("no resolver");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(calls, 0);
    }

    #[test]
    fn ipv6_dns_reaches_only_ipv6_resolvers() {
        let none = joined(&ipv6_drop_steps(&[]));
        assert!(!none.iter().any(|l| l.contains("--dport 53")), "{none:?}");
        let s = joined(&ipv6_drop_steps(&["2001:db8::53".to_string()]));
        for proto in ["udp", "tcp"] {
            assert!(s.contains(&format!(
                "-A RUNEBOX_OUT6 -p {proto} -d 2001:db8::53 --dport 53 -j RETURN"
            )));
        }
        let drop = s.iter().position(|l| l == "-A RUNEBOX_OUT6 -j DROP");
        assert!(s.iter().position(|l| l.contains("-d 2001:db8::53")) < drop);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_off_linux() {
        let err = setup_redirect(1337, 15001).expect_err("unsupported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
