import asyncio

from backend.scanner.passive.dns_checks import DnsRecords, candidate_domains, collect_dns_records, evaluate_dns_records


def _categories(**fields) -> set[str]:
    return {f.category for f in evaluate_dns_records("example.com", DnsRecords(**fields))}


def test_candidate_domains_walk_up_to_two_labels() -> None:
    assert candidate_domains("www.shop.example.com") == ["www.shop.example.com", "shop.example.com", "example.com"]
    assert candidate_domains("example.com") == ["example.com"]


def test_mail_domain_without_spf_and_dmarc_is_flagged() -> None:
    assert _categories(a=["1.2.3.4"], mx=["10 mail.example.com."], caa=["0 issue letsencrypt.org"]) == {
        "DNS_MISSING_SPF",
        "DNS_MISSING_DMARC",
    }


def test_domain_without_mail_does_not_get_mail_findings() -> None:
    assert _categories(a=["1.2.3.4"], caa=["0 issue letsencrypt.org"]) == set()


def test_permissive_spf_and_monitor_only_dmarc() -> None:
    cats = _categories(
        a=["1.2.3.4"], mx=["10 m."], caa=["0 issue x"],
        txt=["v=spf1 +all"], dmarc=["v=DMARC1; p=none"],
    )
    assert cats == {"DNS_PERMISSIVE_SPF", "DNS_DMARC_MONITOR_ONLY"}


def test_missing_caa_is_informational_only() -> None:
    findings = evaluate_dns_records("example.com", DnsRecords(a=["1.2.3.4"]))
    assert [(f.category, f.severity) for f in findings] == [("DNS_MISSING_CAA", "INFO")]


def test_ip_literals_and_local_names_skip_dns() -> None:
    assert asyncio.run(collect_dns_records("127.0.0.1")) is None
    assert asyncio.run(collect_dns_records("localhost")) is None
    assert asyncio.run(collect_dns_records("printer.local")) is None
