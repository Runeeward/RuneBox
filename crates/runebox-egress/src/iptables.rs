//! iptables/ip6tables rules that force sandbox egress through the
//! transparent proxy (strict / L3 mode). Rule construction is portable and
//! unit-tested; executing it is Linux-only.

use std::io;
use std::net::IpAddr;

/// Optionally restricts DNS egress to a comma-separated list of resolver IPs.
/// When set, DNS (port 53) to any other destination is dropped, so a workload
/// can't tunnel data out over DNS to an arbitrary server. Unset keeps DNS
/// open.
pub const DNS_RESOLVERS_ENV: &str = "RUNEBOX_DNS_RESOLVERS";

/// nat-table chain redirecting outbound TCP to the proxy.
pub const CHAIN: &str = "RUNEBOX_OUT";
/// filter-table chain dropping non-DNS UDP.
pub const UDP_CHAIN: &str = "RUNEBOX_UDP";
/// filter-table chain confining TCP DNS to the pinned resolvers.
pub const DNS_TCP_CHAIN: &str = "RUNEBOX_DNST";
/// filter-table chain dropping outbound ICMP that isn't a reply.
pub const ICMP_CHAIN: &str = "RUNEBOX_ICMP";
/// ip6tables chain dropping IPv6 egress.
pub const CHAIN6: &str = "RUNEBOX_OUT6";

/// Returns the valid resolver IPs from a `RUNEBOX_DNS_RESOLVERS` value
/// (garbage entries are skipped rather than failing setup).
pub fn parse_dns_resolvers(raw: &str) -> Vec<String> {
    raw.trim()
        .split(',')
        .map(str::trim)
        .filter(|f| !f.is_empty() && f.parse::<IpAddr>().is_ok())
        .map(str::to_string)
        .collect()
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
        args(&[
            "-t", "filter", "-D", "OUTPUT", "-p", "icmp", "-j", ICMP_CHAIN,
        ]),
        args(&["-t", "filter", "-F", ICMP_CHAIN]),
        args(&["-t", "filter", "-X", ICMP_CHAIN]),
    ]
}

/// One rule of [`icmp_steps`] and whether setup fails when it can't be
/// installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpStep {
    /// The iptables arguments.
    pub args: Vec<String>,
    /// A failure aborts setup. Only the conntrack reply exemption is
    /// optional: without it (gVisor has no conntrack match) all outbound
    /// ICMP is dropped, which is stricter.
    pub required: bool,
}

/// The IPv4 rules (in order) that drop outbound ICMP except loopback and
/// replies or errors belonging to an existing flow (conntrack ESTABLISHED
/// or RELATED). A workload can't ping out, probe the network or tunnel
/// data over ICMP; path MTU discovery and errors for allowed flows still
/// work.
pub fn icmp_steps() -> Vec<IcmpStep> {
    let step = |a: &[&str], required: bool| IcmpStep {
        args: args(a),
        required,
    };
    vec![
        step(&["-t", "filter", "-N", ICMP_CHAIN], true),
        step(
            &["-t", "filter", "-A", ICMP_CHAIN, "-o", "lo", "-j", "RETURN"],
            true,
        ),
        step(
            &[
                "-t",
                "filter",
                "-A",
                ICMP_CHAIN,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "RETURN",
            ],
            false,
        ),
        step(&["-t", "filter", "-A", ICMP_CHAIN, "-j", "DROP"], true),
        step(
            &[
                "-t", "filter", "-A", "OUTPUT", "-p", "icmp", "-j", ICMP_CHAIN,
            ],
            true,
        ),
    ]
}

/// The IPv4 rules (in order) that redirect outbound TCP to `redirect_port`,
/// exempting `proxy_uid`, loopback and DNS; drop non-DNS UDP (QUIC/HTTP3
/// bypass); and, when `resolvers` is non-empty, confine UDP and TCP DNS to
/// them.
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
        // Let DNS through (not redirected) so name resolution keeps working;
        // destination filtering, if any, happens in the filter table below.
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
    // DNS destination policy for UDP: only the configured resolvers when set,
    // otherwise any :53. Everything else falls through to the DROP.
    if resolvers.is_empty() {
        steps.push(args(&[
            "-t", "filter", "-A", UDP_CHAIN, "-p", "udp", "--dport", "53", "-j", "RETURN",
        ]));
    } else {
        for ip in resolvers {
            steps.push(args(&[
                "-t", "filter", "-A", UDP_CHAIN, "-p", "udp", "-d", ip, "--dport", "53", "-j",
                "RETURN",
            ]));
        }
    }
    steps.push(args(&[
        "-t", "filter", "-A", UDP_CHAIN, "-p", "udp", "-j", "DROP",
    ]));
    steps.push(args(&[
        "-t", "filter", "-A", "OUTPUT", "-p", "udp", "-j", UDP_CHAIN,
    ]));

    // With pinned resolvers, also confine TCP DNS (DoT/large responses) so DNS
    // can't be a covert channel over TCP either.
    if !resolvers.is_empty() {
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
    }
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

/// ip6tables rules dropping all IPv6 egress except loopback and DNS (the
/// proxy is IPv4-only, so this forces traffic onto the proxied path).
pub fn ipv6_drop_steps() -> Vec<Vec<String>> {
    vec![
        args(&["-N", CHAIN6]),
        args(&["-A", CHAIN6, "-o", "lo", "-j", "RETURN"]),
        args(&["-A", CHAIN6, "-p", "udp", "--dport", "53", "-j", "RETURN"]),
        args(&["-A", CHAIN6, "-p", "tcp", "--dport", "53", "-j", "RETURN"]),
        args(&["-A", CHAIN6, "-j", "DROP"]),
        args(&["-A", "OUTPUT", "-j", CHAIN6]),
    ]
}

/// Runs the full setup sequence through `run(program, args)`: best-effort
/// flush, fail-fast IPv4 steps (TCP/UDP, then ICMP), then best-effort IPv6
/// drop.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn setup_redirect_with<F>(
    mut run: F,
    proxy_uid: u32,
    redirect_port: u16,
    resolvers: &[String],
) -> io::Result<()>
where
    F: FnMut(&str, &[String]) -> io::Result<()>,
{
    let (v4, v6) = pick_backend(&mut run);
    for a in flush_steps() {
        let _ = run(v4, &a);
    }
    let fail = |a: &[String], e: io::Error| {
        // gVisor has no nftables, and its legacy nat table exists only
        // with runsc's net-raw option.
        let hint = if e.to_string().contains("nft") {
            " (under gVisor, set net-raw = \"true\" in runsc's configuration)"
        } else {
            ""
        };
        io::Error::new(e.kind(), format!("{v4} {}: {e}{hint}", a.join(" ")))
    };
    for a in redirect_steps(proxy_uid, redirect_port, resolvers) {
        run(v4, &a).map_err(|e| fail(&a, e))?;
    }
    for s in icmp_steps() {
        match run(v4, &s.args) {
            Err(e) if s.required => return Err(fail(&s.args, e)),
            _ => {}
        }
    }
    // Some environments lack IPv6/ip6tables entirely, which is fine (nothing
    // to bypass through), so failures here are ignored.
    for a in ipv6_flush_steps().into_iter().chain(ipv6_drop_steps()) {
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
/// proxy on `redirect_port`, exempting `proxy_uid`, loopback and DNS, and
/// closing the UDP/QUIC, ICMP and IPv6 bypasses. Reads [`DNS_RESOLVERS_ENV`]. Runs
/// once, privileged, before the sandbox starts.
#[cfg(target_os = "linux")]
pub fn setup_redirect(proxy_uid: u32, redirect_port: u16) -> io::Result<()> {
    let resolvers = parse_dns_resolvers(&std::env::var(DNS_RESOLVERS_ENV).unwrap_or_default());
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

    #[test]
    fn parse_resolvers_skips_garbage() {
        assert!(parse_dns_resolvers("").is_empty());
        assert_eq!(
            parse_dns_resolvers(" 1.1.1.1, nope ,,2606:4700::1111 "),
            vec!["1.1.1.1".to_string(), "2606:4700::1111".to_string()]
        );
    }

    fn joined(steps: &[Vec<String>]) -> Vec<String> {
        steps.iter().map(|s| s.join(" ")).collect()
    }

    #[test]
    fn steps_without_resolvers() {
        let s = joined(&redirect_steps(1337, 15001, &[]));
        assert_eq!(s[0], "-t nat -N RUNEBOX_OUT");
        assert!(
            s.contains(&"-t nat -A RUNEBOX_OUT -m owner --uid-owner 1337 -j RETURN".to_string())
        );
        assert!(
            s.contains(&"-t nat -A RUNEBOX_OUT -p tcp -j REDIRECT --to-ports 15001".to_string())
        );
        assert!(s.contains(&"-t filter -A RUNEBOX_UDP -p udp --dport 53 -j RETURN".to_string()));
        assert_eq!(
            s.last().map(String::as_str),
            Some("-t filter -A OUTPUT -p udp -j RUNEBOX_UDP")
        );
        assert!(!s.iter().any(|l| l.contains("RUNEBOX_DNST")));
        assert_eq!(s.len(), 13);
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
            &[],
        );
        assert!(res.is_ok());
        assert_eq!(
            calls.len(),
            1 + flush_steps().len() + 13 + icmp_steps().len() + 9
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
            &[],
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
            &[],
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
            &[],
        )
        .expect_err("must fail");
        assert_eq!(progs[..2], ["iptables", "iptables-legacy"]);
        assert!(progs[2..].iter().all(|p| p == "iptables"), "{progs:?}");
        assert!(err.to_string().starts_with("iptables "), "{err}");
        assert!(!err.to_string().contains("gVisor"), "{err}");
    }

    #[test]
    fn icmp_drops_all_but_replies() {
        let steps = icmp_steps();
        let s: Vec<String> = steps.iter().map(|s| s.args.join(" ")).collect();
        assert_eq!(
            s,
            [
                "-t filter -N RUNEBOX_ICMP",
                "-t filter -A RUNEBOX_ICMP -o lo -j RETURN",
                "-t filter -A RUNEBOX_ICMP -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
                "-t filter -A RUNEBOX_ICMP -j DROP",
                "-t filter -A OUTPUT -p icmp -j RUNEBOX_ICMP",
            ]
        );
        // Only the reply exemption may fail; losing it is stricter.
        let optional: Vec<&str> = steps
            .iter()
            .filter(|s| !s.required)
            .map(|s| s.args[3].as_str())
            .collect();
        assert_eq!(optional, ["RUNEBOX_ICMP"]);
        assert!(!steps[2].required && steps[2].args.contains(&"conntrack".to_string()));
        assert!(
            flush_steps()
                .iter()
                .any(|a| a.join(" ") == "-t filter -X RUNEBOX_ICMP")
        );
    }

    #[test]
    fn setup_installs_icmp_rules_after_redirect() {
        let mut calls = Vec::new();
        setup_redirect_with(
            |prog, a| {
                calls.push(format!("{prog} {}", a.join(" ")));
                Ok(())
            },
            1337,
            15001,
            &[],
        )
        .expect("setup");
        let redirect = calls
            .iter()
            .position(|c| c == "iptables -t nat -A OUTPUT -p tcp -j RUNEBOX_OUT")
            .expect("redirect");
        let jump = calls
            .iter()
            .position(|c| c == "iptables -t filter -A OUTPUT -p icmp -j RUNEBOX_ICMP")
            .expect("icmp jump");
        let drop = calls
            .iter()
            .position(|c| c == "iptables -t filter -A RUNEBOX_ICMP -j DROP")
            .expect("icmp drop");
        assert!(redirect < drop && drop < jump);
    }

    #[test]
    fn missing_conntrack_keeps_the_icmp_drop() {
        let mut calls = Vec::new();
        setup_redirect_with(
            |prog, a| {
                calls.push(format!("{prog} {}", a.join(" ")));
                if a.iter().any(|x| x == "conntrack") {
                    Err(io::Error::other("no conntrack match"))
                } else {
                    Ok(())
                }
            },
            1337,
            15001,
            &[],
        )
        .expect("conntrack is optional");
        assert!(calls.contains(&"iptables -t filter -A RUNEBOX_ICMP -j DROP".to_string()));
    }

    #[test]
    fn icmp_rule_failure_aborts_setup() {
        let err = setup_redirect_with(
            |_, a| {
                if a.join(" ") == "-t filter -A RUNEBOX_ICMP -j DROP" {
                    Err(io::Error::other("boom"))
                } else {
                    Ok(())
                }
            },
            1,
            2,
            &[],
        )
        .expect_err("must fail");
        assert!(
            err.to_string().contains("RUNEBOX_ICMP -j DROP: boom"),
            "{err}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_off_linux() {
        let err = setup_redirect(1337, 15001).expect_err("unsupported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
