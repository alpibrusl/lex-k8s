//! The spend adapter (alpibrusl/lex-k8s#1 milestone 4).
//!
//! A namespace's spend, charged against `Budget::max_money_cents` — the
//! same integer-cents ceiling lex-iac charges a Terraform plan against,
//! and the same rule: **money never touches a float**.
//!
//! # A pod's cost is computable; a namespace's is not
//!
//! This is the one place the Kubernetes gate has *more* to work with
//! than the Terraform one. lex-iac cannot price a plan — it takes an
//! estimator's JSON — but a pod declares what it wants reserved, and
//! `requests × rate` is arithmetic. So the forecast for the pod under
//! review is computed here, from the spec, and only two things are
//! supplied: the [`PriceList`] and what the namespace is already
//! spending.
//!
//! Both are inputs rather than lookups, for the reason the whole repo
//! keeps rediscovering: an admission webhook that phones a billing API
//! is a webhook that fails when billing does, and `failurePolicy: Fail`
//! turns that into a cluster that cannot schedule.
//!
//! # Requests, not limits
//!
//! Requests are what the scheduler reserves and what every cost tool
//! bills against. A pod is charged for what it holds, not for what it
//! is permitted to burst to. Limits bound a different question, and
//! charging them would refuse pods that never spend the money.
//!
//! # This is a ceiling on committed spend, not a meter
//!
//! `requests × list rate` ignores actual utilisation, spot pricing,
//! reservations and every discount an organisation has negotiated. It
//! bounds what a namespace has *committed to reserving*, which is a
//! different and more tractable question than what the invoice says.

use serde::{Deserialize, Serialize};

use crate::spec::{Container, ContainerKind};

/// Why spend could not be read.
///
/// Every variant refuses. There is no "assume zero": a quantity nobody
/// could parse is not a quantity of nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CostError {
    #[error("{what} is not JSON: {why}")]
    NotJson { what: String, why: String },
    #[error(
        "container `{container}` declares {field}: `{value}`, which is not a \
         Kubernetes quantity — a request nobody can read cannot be charged"
    )]
    NotAQuantity {
        container: String,
        field: String,
        value: String,
    },
    #[error(
        "the spend report is in {report}, but the grant's budget is denominated \
         in {expected} — comparing them would silently mis-size the ceiling"
    )]
    CurrencyMismatch { report: String, expected: String },
}

/// What a core-month and a GiB-month cost, in integer minor units.
///
/// Supplied by the operator, from whatever their cloud actually
/// charges. There is no default: a made-up rate produces a
/// confident-looking number that is wrong, which is worse than no
/// number at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceList {
    /// ISO 4217, upper-cased.
    pub currency: String,
    /// Minor units per CPU core per month.
    pub cpu_core_month_minor: u64,
    /// Minor units per GiB of memory per month.
    pub gib_month_minor: u64,
}

impl PriceList {
    pub fn from_json(src: &str) -> Result<Self, CostError> {
        let mut p: PriceList = serde_json::from_str(src).map_err(|e| CostError::NotJson {
            what: "the price list".to_string(),
            why: e.to_string(),
        })?;
        p.currency = p.currency.to_uppercase();
        Ok(p)
    }

    /// Price one pod's reservation, in minor units per month.
    ///
    /// Integer arithmetic throughout. CPU is in millicores and memory
    /// in bytes, so the divisors are exact and the rounding is one
    /// truncation at the end rather than an accumulating drift.
    pub fn price(&self, r: &Reservation) -> u64 {
        let cpu = (r.cpu_millicores as u128 * self.cpu_core_month_minor as u128) / 1000;
        let mem = (r.memory_bytes as u128 * self.gib_month_minor as u128) / (1024 * 1024 * 1024);
        (cpu + mem).min(u64::MAX as u128) as u64
    }
}

/// What a namespace is already spending, per month, in minor units.
///
/// From OpenCost, Kubecost, or a finance export — whatever the
/// operator already runs. It is a number this crate is told, never one
/// it goes and fetches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendReport {
    /// ISO 4217, upper-cased.
    pub currency: String,
    /// The namespace's current committed monthly spend.
    pub namespace_monthly_minor: u64,
}

impl SpendReport {
    pub fn from_json(src: &str) -> Result<Self, CostError> {
        let mut s: SpendReport = serde_json::from_str(src).map_err(|e| CostError::NotJson {
            what: "the spend report".to_string(),
            why: e.to_string(),
        })?;
        s.currency = s.currency.to_uppercase();
        Ok(s)
    }

    pub fn check_currency(&self, expected: &str) -> Result<(), CostError> {
        if self.currency.eq_ignore_ascii_case(expected) {
            Ok(())
        } else {
            Err(CostError::CurrencyMismatch {
                report: self.currency.clone(),
                expected: expected.to_string(),
            })
        }
    }
}

/// What a pod asks the scheduler to reserve.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    pub cpu_millicores: u64,
    pub memory_bytes: u64,
}

impl Reservation {
    fn max(self, other: Self) -> Self {
        Reservation {
            cpu_millicores: self.cpu_millicores.max(other.cpu_millicores),
            memory_bytes: self.memory_bytes.max(other.memory_bytes),
        }
    }

    fn plus(self, other: Self) -> Self {
        Reservation {
            cpu_millicores: self.cpu_millicores.saturating_add(other.cpu_millicores),
            memory_bytes: self.memory_bytes.saturating_add(other.memory_bytes),
        }
    }
}

/// A container that declared no request at all.
///
/// Not an error and not a zero: the same distinction the rest of this
/// repo draws between "we looked and it was nothing" and "nobody
/// said". The wall decides what to do with it — see
/// [`effective_requests`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Undeclared {
    pub container: String,
    pub kind: String,
}

/// A pod's effective reservation, and the containers that declared
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodReservation {
    pub reservation: Reservation,
    /// Containers with no `resources.requests` at all.
    ///
    /// **An empty request is not a request for nothing.** A container
    /// with none is scheduled as BestEffort and can use whatever the
    /// node has going spare, so pricing it at zero would make omitting
    /// requests the cheapest way past a budget — the exact evasion this
    /// wall exists to prevent. The wall refuses when any are present
    /// and a budget is being enforced.
    pub undeclared: Vec<Undeclared>,
}

/// A pod's effective reservation, by Kubernetes' own rule.
///
/// Not the sum of every container. Init containers run **sequentially,
/// before** the app containers, so the pod's reservation is the larger
/// of what the init phase needs and what the running phase needs:
///
/// ```text
/// max( max over init containers,
///      sum over app containers + sidecars )
/// ```
///
/// Getting this wrong overcharges every pod with a heavyweight init
/// container — a database migration that wants 2 cores for 30 seconds
/// would be billed as if it ran for the month, and an operator whose
/// budget refuses that pod has been told a falsehood about their
/// spend.
///
/// **Sidecars are in the sum, not the max.** A `restartPolicy: Always`
/// init container (k8s 1.29+) runs for the pod's whole life, so its
/// reservation is held alongside the app containers rather than
/// released before they start. This repo already distinguishes them for
/// authority; the same distinction is load-bearing for money.
///
/// **Ephemeral containers reserve nothing.** Kubernetes forbids
/// `resources` on them outright — they are scheduled into a pod that
/// already exists, with no guarantees — so a debug container cannot
/// change what a pod costs, and one that somehow declared a request is
/// ignored rather than charged.
pub fn effective_requests(
    containers: &[(ContainerKind, &Container)],
) -> Result<PodReservation, CostError> {
    let mut running = Reservation::default();
    let mut init_peak = Reservation::default();
    let mut undeclared = Vec::new();

    for (kind, c) in containers {
        if *kind == ContainerKind::Ephemeral {
            continue;
        }
        let cpu = match &c.resources.requests.cpu {
            Some(q) => Some(parse_cpu(q).ok_or_else(|| CostError::NotAQuantity {
                container: c.name.clone(),
                field: "resources.requests.cpu".to_string(),
                value: q.clone(),
            })?),
            None => None,
        };
        let memory = match &c.resources.requests.memory {
            Some(q) => Some(parse_memory(q).ok_or_else(|| CostError::NotAQuantity {
                container: c.name.clone(),
                field: "resources.requests.memory".to_string(),
                value: q.clone(),
            })?),
            None => None,
        };
        if cpu.is_none() && memory.is_none() {
            undeclared.push(Undeclared {
                container: c.name.clone(),
                kind: kind.as_str().to_string(),
            });
            continue;
        }
        let r = Reservation {
            cpu_millicores: cpu.unwrap_or(0),
            memory_bytes: memory.unwrap_or(0),
        };
        match kind {
            ContainerKind::Init => init_peak = init_peak.max(r),
            ContainerKind::App | ContainerKind::Sidecar => running = running.plus(r),
            ContainerKind::Ephemeral => unreachable!("skipped above"),
        }
    }

    Ok(PodReservation {
        reservation: running.max(init_peak),
        undeclared,
    })
}

/// Parse a Kubernetes CPU quantity into millicores.
///
/// `100m` → 100, `0.5` → 500, `2` → 2000. Decimal forms are read digit
/// by digit rather than through an `f64`: `0.1` has no exact binary
/// representation, and a reservation that drifts by a rounding error is
/// one nobody can reconcile against a bill.
pub fn parse_cpu(q: &str) -> Option<u64> {
    let q = q.trim();
    if q.is_empty() {
        return None;
    }
    if let Some(milli) = q.strip_suffix('m') {
        return milli.parse::<u64>().ok();
    }
    // A plain decimal number of cores, scaled by 1000.
    scale_decimal(q, 3)
}

/// Parse a Kubernetes memory quantity into bytes.
///
/// Both suffix families, because Kubernetes accepts both and they are
/// not the same number: `1Mi` is 1048576 and `1M` is 1000000. Treating
/// them alike understates memory by 4.9% at Gi scale, always in the
/// direction that flatters the pod.
pub fn parse_memory(q: &str) -> Option<u64> {
    let q = q.trim();
    if q.is_empty() {
        return None;
    }
    const BINARY: &[(&str, u64)] = &[
        ("Ki", 1 << 10),
        ("Mi", 1 << 20),
        ("Gi", 1 << 30),
        ("Ti", 1u64 << 40),
        ("Pi", 1u64 << 50),
    ];
    const DECIMAL: &[(&str, u64)] = &[
        ("k", 1_000),
        ("K", 1_000),
        ("M", 1_000_000),
        ("G", 1_000_000_000),
        ("T", 1_000_000_000_000),
        ("P", 1_000_000_000_000_000),
    ];
    // Binary first: `Mi` also ends in `i`, and a `M` match would take
    // the wrong branch.
    for (suffix, mult) in BINARY {
        if let Some(n) = q.strip_suffix(suffix) {
            return n.trim().parse::<u64>().ok()?.checked_mul(*mult);
        }
    }
    for (suffix, mult) in DECIMAL {
        if let Some(n) = q.strip_suffix(suffix) {
            return n.trim().parse::<u64>().ok()?.checked_mul(*mult);
        }
    }
    q.parse::<u64>().ok()
}

/// `"1.5"` with `places = 3` → `1500`. No float, ever.
fn scale_decimal(src: &str, places: u32) -> Option<u64> {
    let (whole, frac) = match src.split_once('.') {
        Some((w, f)) => (w, f),
        None => (src, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    if !whole.chars().all(|c| c.is_ascii_digit())
        || !frac.chars().all(|c| c.is_ascii_digit())
        // More precision than the unit can hold is a quantity we would
        // have to round. Refuse rather than silently truncate.
        || frac.len() > places as usize
    {
        return None;
    }
    let scale = 10u64.checked_pow(places)?;
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let mut f: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse().ok()?
    };
    for _ in 0..(places as usize - frac.len()) {
        f = f.checked_mul(10)?;
    }
    whole.checked_mul(scale)?.checked_add(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{ResourceList, Resources};

    fn c(name: &str, cpu: Option<&str>, mem: Option<&str>) -> Container {
        Container {
            name: name.to_string(),
            resources: Resources {
                requests: ResourceList {
                    cpu: cpu.map(String::from),
                    memory: mem.map(String::from),
                },
            },
            ..Default::default()
        }
    }

    #[test]
    fn cpu_quantities_parse_without_a_float() {
        assert_eq!(parse_cpu("100m"), Some(100));
        assert_eq!(parse_cpu("1"), Some(1000));
        assert_eq!(parse_cpu("0.5"), Some(500));
        assert_eq!(parse_cpu("2.25"), Some(2250));
        assert_eq!(parse_cpu("0.001"), Some(1));
        assert_eq!(parse_cpu(""), None);
        assert_eq!(parse_cpu("half"), None);
        // More precision than a millicore holds is refused, not rounded.
        assert_eq!(parse_cpu("0.0001"), None);
    }

    /// `1Mi` and `1M` are different numbers, and the difference always
    /// runs in the pod's favour if you conflate them.
    #[test]
    fn binary_and_decimal_memory_suffixes_are_not_the_same() {
        assert_eq!(parse_memory("1Mi"), Some(1_048_576));
        assert_eq!(parse_memory("1M"), Some(1_000_000));
        assert_eq!(parse_memory("1Gi"), Some(1_073_741_824));
        assert_eq!(parse_memory("512Mi"), Some(536_870_912));
        assert_eq!(parse_memory("1024"), Some(1024));
        assert_eq!(parse_memory("lots"), None);
    }

    /// Kubernetes' own formula, and the reason it is not a sum: a
    /// heavyweight migration that runs for 30 seconds must not be
    /// billed as if it ran all month.
    #[test]
    fn init_containers_are_a_peak_not_a_sum() {
        let migrate = c("migrate", Some("2"), Some("1Gi"));
        let api = c("api", Some("500m"), Some("512Mi"));
        let r = effective_requests(&[(ContainerKind::Init, &migrate), (ContainerKind::App, &api)])
            .unwrap();
        // max(2000, 500) and max(1Gi, 512Mi) — not 2500 / 1.5Gi.
        assert_eq!(r.reservation.cpu_millicores, 2000);
        assert_eq!(r.reservation.memory_bytes, 1 << 30);
    }

    /// A sidecar runs for the pod's whole life, so it is held alongside
    /// the app containers rather than released before them.
    #[test]
    fn sidecars_are_in_the_sum_not_the_peak() {
        let proxy = c("proxy", Some("200m"), Some("128Mi"));
        let api = c("api", Some("500m"), Some("512Mi"));
        let r = effective_requests(&[(ContainerKind::Sidecar, &proxy), (ContainerKind::App, &api)])
            .unwrap();
        assert_eq!(r.reservation.cpu_millicores, 700);
        assert_eq!(r.reservation.memory_bytes, (512 << 20) + (128 << 20));
    }

    /// Kubernetes forbids `resources` on an ephemeral container, so a
    /// debug container cannot change what a pod costs.
    #[test]
    fn ephemeral_containers_reserve_nothing() {
        let api = c("api", Some("500m"), Some("512Mi"));
        let debug = c("debug", Some("4"), Some("8Gi"));
        let r = effective_requests(&[
            (ContainerKind::App, &api),
            (ContainerKind::Ephemeral, &debug),
        ])
        .unwrap();
        assert_eq!(r.reservation.cpu_millicores, 500);
        // And it is not reported as undeclared either — it is not that
        // nobody said, it is that the field does not apply.
        assert!(r.undeclared.is_empty());
    }

    /// An empty request is not a request for nothing.
    #[test]
    fn a_container_with_no_requests_is_reported_not_priced_at_zero() {
        let api = c("api", None, None);
        let r = effective_requests(&[(ContainerKind::App, &api)]).unwrap();
        assert_eq!(r.reservation, Reservation::default());
        assert_eq!(r.undeclared.len(), 1);
        assert_eq!(r.undeclared[0].container, "api");
    }

    /// Half a declaration is still a declaration: the container asked
    /// for CPU, so it is charged for CPU rather than dismissed.
    #[test]
    fn a_partial_request_is_charged_for_what_it_names() {
        let api = c("api", Some("500m"), None);
        let r = effective_requests(&[(ContainerKind::App, &api)]).unwrap();
        assert_eq!(r.reservation.cpu_millicores, 500);
        assert_eq!(r.reservation.memory_bytes, 0);
        assert!(r.undeclared.is_empty());
    }

    /// A quantity nobody can parse is refused, not rounded and not
    /// skipped — skipping it is the direction that flatters the pod.
    #[test]
    fn an_unreadable_quantity_is_an_error() {
        let api = c("api", Some("half a core"), None);
        let e = effective_requests(&[(ContainerKind::App, &api)]).unwrap_err();
        assert!(matches!(e, CostError::NotAQuantity { .. }));
        assert!(e.to_string().contains("half a core"));
    }

    #[test]
    fn pricing_is_integer_arithmetic() {
        let prices = PriceList {
            currency: "USD".into(),
            cpu_core_month_minor: 3_000,
            gib_month_minor: 400,
        };
        // Half a core and 2 GiB: 1500 + 800.
        let r = Reservation {
            cpu_millicores: 500,
            memory_bytes: 2 << 30,
        };
        assert_eq!(prices.price(&r), 2_300);
    }

    #[test]
    fn a_report_in_another_currency_is_refused_rather_than_converted() {
        let s = SpendReport {
            currency: "EUR".into(),
            namespace_monthly_minor: 100,
        };
        assert!(s.check_currency("USD").is_err());
        assert!(s.check_currency("eur").is_ok());
    }
}
