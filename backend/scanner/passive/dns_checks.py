import ipaddress
from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class DnsCheckFinding:
    __slots__ = ("category", "severity", "recommendation", "evidence")

    def __init__(self, category: str, severity: Severity, recommendation: str, evidence: dict[str, Any]) -> None:
        self.category = category
        self.severity = severity
        self.recommendation = recommendation
        self.evidence = evidence


@dataclass
class DnsRecords:
    """Records collected for a hostname. TXT-derived fields already come from the nearest ancestor that has them."""

    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    dmarc: list[str] = field(default_factory=list)
    caa: list[str] = field(default_factory=list)


def candidate_domains(host: str) -> list[str]:
    """The host plus its parents down to two labels. DMARC/CAA policy is inherited from parent domains."""
    labels = host.lower().strip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def evaluate_dns_records(host: str, records: DnsRecords) -> list[DnsCheckFinding]:
    """Pure evaluation of collected DNS data. Findings are informational: DNS alone never proves a weakness."""
    findings: list[DnsCheckFinding] = []
    handles_mail = bool(records.mx)
    spf = [r for r in records.txt if r.lower().startswith("v=spf1")]
    dmarc = [r for r in records.dmarc if r.lower().startswith("v=dmarc1")]

    if handles_mail and not spf:
        findings.append(
            DnsCheckFinding(
                category="DNS_MISSING_SPF",
                severity="LOW",
                recommendation="Publish an SPF TXT record that lists the servers allowed to send mail for this domain.",
                evidence={"host": host, "mx": records.mx[:5]},
            )
        )
    elif spf and any(r.lower().rstrip().endswith("+all") for r in spf):
        findings.append(
            DnsCheckFinding(
                category="DNS_PERMISSIVE_SPF",
                severity="MEDIUM",
                recommendation="Replace '+all' with '-all' or '~all' so unauthorised senders are not accepted.",
                evidence={"host": host, "record": spf[0]},
            )
        )

    if handles_mail and not dmarc:
        findings.append(
            DnsCheckFinding(
                category="DNS_MISSING_DMARC",
                severity="LOW",
                recommendation="Publish a DMARC record at _dmarc.<domain>, starting with p=none and moving towards quarantine or reject.",
                evidence={"host": host},
            )
        )
    elif dmarc and any("p=none" in r.lower().replace(" ", "") for r in dmarc):
        findings.append(
            DnsCheckFinding(
                category="DNS_DMARC_MONITOR_ONLY",
                severity="INFO",
                recommendation="DMARC is in monitoring mode (p=none). Move to quarantine or reject once reports look clean.",
                evidence={"host": host, "record": dmarc[0]},
            )
        )

    if (records.a or records.aaaa) and not records.caa:
        findings.append(
            DnsCheckFinding(
                category="DNS_MISSING_CAA",
                severity="INFO",
                recommendation="Optionally publish CAA records to restrict which certificate authorities may issue certificates.",
                evidence={"host": host},
            )
        )

    return findings


async def collect_dns_records(host: str, *, timeout: float = 3.0) -> DnsRecords | None:
    """Queries public DNS for the host. Returns None for IP literals, local names, or when DNS is unavailable."""
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if "." not in host or host.endswith((".local", ".localhost", ".internal")):
        return None

    import dns.asyncresolver
    import dns.exception

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    async def query(name: str, rtype: str) -> list[str]:
        try:
            answer = await resolver.resolve(name, rtype)
        except (dns.exception.DNSException, OSError):
            return []
        return [r.to_text().strip('"') for r in answer]

    records = DnsRecords()
    records.a = await query(host, "A")
    records.aaaa = await query(host, "AAAA")
    records.cname = await query(host, "CNAME")
    for domain in candidate_domains(host):
        if not records.mx:
            records.mx = await query(domain, "MX")
        if not any(t.lower().startswith("v=spf1") for t in records.txt):
            records.txt += [t.replace('" "', "") for t in await query(domain, "TXT")]
        if not records.dmarc:
            records.dmarc = [t.replace('" "', "") for t in await query(f"_dmarc.{domain}", "TXT")]
        if not records.caa:
            records.caa = await query(domain, "CAA")
    return records


async def run_dns_checks(host: str) -> list[DnsCheckFinding]:
    records = await collect_dns_records(host)
    return evaluate_dns_records(host, records) if records else []
