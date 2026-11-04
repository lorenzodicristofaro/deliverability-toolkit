"""Integration tests for the `unbound` compose profile. Run with `pytest -m integration`.

Need Docker (compose, buildx) and outbound DNS. CI job: "integration-unbound" (ci.yml).
Clients run in throwaway containers of the same image (it ships `drill`) on the `dns` network.
"""

from __future__ import annotations

import ipaddress
import json
import secrets
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.dnssec_tag import root_key_tags
from tests.integration.stack import REPO, UNBOUND_IP, Stack, host_probe_is_unbound, run

pytestmark = pytest.mark.integration

# Spamhaus ZEN return codes, https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html
# DNSBL provider constants (one place, to swap the provider).
DNSBL_TEST_NAME = "2.0.0.127.zen.spamhaus.org"  # reversed test target 127.0.0.2 (listed)
DNSBL_CLEAN_NAME = "1.0.0.127.zen.spamhaus.org"  # reversed 127.0.0.1 (documented not listed)
ZEN_CODES = {
    "127.0.0.2",
    "127.0.0.3",
    "127.0.0.4",
    "127.0.0.9",
    "127.0.0.10",
    "127.0.0.11",
    "127.0.0.30",
}


def _inspect(stack: Stack) -> dict:  # type: ignore[type-arg]
    return json.loads(run("docker", "inspect", stack.container).stdout)[0]  # type: ignore[no-any-return]


# --- trust anchor (A1) -------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/var/lib/unbound/root.key", "/usr/share/dns/root.key"])
def test_image_trust_anchor_has_ksk_2024(stack: Stack, path: str) -> None:
    """Key tag 38696 (KSK-2024, sole root DNSKEY signer since 2026-10-11) is in the built image.

    The tag is computed from the DNSKEY records (RFC 4034 App. B), not grepped. `docker run`
    without a volume shows the image content (the seed), not the compose volume.
    """
    text = run("docker", "run", "--rm", "--entrypoint", "cat", stack.image, path).stdout
    assert 38696 in root_key_tags(text)


# --- resolution behaviour (D) ------------------------------------------------------------------


def test_dnssec_validation_sets_ad(stack: Stack) -> None:
    ans = stack.drill("-D", "ietf.org", "A")
    assert ans.rcode == "NOERROR", ans.raw
    assert "ad" in ans.flags, ans.raw


def test_bad_signature_is_servfail_and_cd_proves_validation(stack: Stack) -> None:
    bad = stack.drill("-D", "dnssec-failed.org", "A")
    assert bad.rcode == "SERVFAIL", bad.raw
    # With checking disabled the same name resolves: the failure above was validation.
    cd = stack.drill("-D", "-o", "CD", "dnssec-failed.org", "A")
    assert cd.rcode == "NOERROR", cd.raw
    assert any(t == "A" for t, _ in cd.answers), cd.raw


def test_nxdomain(stack: Stack) -> None:
    name = f"nx-{secrets.token_hex(6)}.invalid"  # RFC 6761; the signed root answers NXDOMAIN
    ans = stack.drill(name, "A")
    assert ans.rcode == "NXDOMAIN", ans.raw


@pytest.fixture
def outside_probe(stack: Stack, tmp_path: Path) -> Iterator[str]:
    """IP of a second unbound (same image, shipped config) reachable from outside the subnet.

    The shipped config only listens on the dns/loopback addresses, so a client elsewhere would
    just time out. To observe the ACL (not the listen address) we start a probe from the same
    image with the shipped unbound.conf where only the `interface:` lines are replaced by
    `interface: 0.0.0.0`, on the compose *default* network (not in 172.28.53.0/24).
    """
    name = f"{stack.project}-probe"
    conf = (REPO / "docker/unbound/unbound.conf").read_text()
    lines = [ln for ln in conf.splitlines() if not ln.strip().startswith("interface:")]
    lines.insert(lines.index("server:") + 1, "    interface: 0.0.0.0")
    probe_conf = tmp_path / "probe-unbound.conf"
    probe_conf.write_text("\n".join(lines) + "\n")
    try:
        run(
            "docker", "create", "--name", name, "--network", f"{stack.project}_default",
            "--entrypoint", "unbound", stack.image, "-d", "-c", "/etc/unbound/unbound.conf",
        )  # fmt: skip
        run("docker", "cp", str(probe_conf), f"{name}:/etc/unbound/unbound.conf.d/toolkit.conf")
        run("docker", "start", name)
        ip = run(
            "docker", "inspect", "-f",
            f"{{{{.NetworkSettings.Networks.{stack.project}_default.IPAddress}}}}", name,
        ).stdout.strip()  # fmt: skip
        assert ipaddress.ip_address(ip) not in ipaddress.ip_network("172.28.53.0/24")
        yield ip
    finally:
        run("docker", "rm", "-f", name, check=False)


def test_query_from_outside_subnet_is_refused(stack: Stack, outside_probe: str) -> None:
    last = ""
    for _ in range(20):  # wait for the probe to listen
        try:
            ans = stack.drill(
                "ietf.org", "A", server=outside_probe, network=f"{stack.project}_default"
            )
        except ValueError as exc:
            last = str(exc)
            time.sleep(1)
            continue
        assert ans.rcode == "REFUSED", ans.raw
        return
    pytest.fail(f"probe never answered: {last}")


# --- DNSBL (D) ---------------------------------------------------------------------------------


def test_dnsbl_test_entry(stack: Stack) -> None:
    """Spamhaus ZEN test entry 2.0.0.127.zen.spamhaus.org (127.0.0.2 = "listed in a Spamhaus zone").

    Sources (read 2026-11-04): https://www.spamhaus.org/faq/section/DNSBL%20Usage (test targets
    127.0.0.2 listed / 127.0.0.1 not listed; 127.255.255.254 = query via public/open resolver,
    127.255.255.255 = excessive queries; free use only non-commercial, low volume, not from a
    public resolver or an IP with generic rDNS, own resolver)
    and https://docs.spamhaus.com/... zones page (ZEN codes). `unverified`: whether queries from
    GitHub-hosted runner IPs are answered; hence a provider-side block skips, it does not fail.
    A provider-side NXDOMAIN (public resolver / generic rDNS get 'not listed' per the FAQ), a
    timeout or an error code skips. A local malfunction still fails: the local-resolution
    precondition below must hold.
    """
    pre = stack.drill("-D", "ietf.org", "A")
    assert pre.rcode == "NOERROR" and "ad" in pre.flags, f"local resolution broken:\n{pre.raw}"

    # A cold cache can SERVFAIL the first lookups while the zone's name servers are resolved
    # (observed): retry before treating it as provider-side.
    for _ in range(4):
        try:
            listed = stack.drill(DNSBL_TEST_NAME, "A")
        except ValueError:  # drill got no response (timeout)
            pytest.skip("provider-side: no response for the DNSBL test entry (timeout)")
        if listed.rcode != "SERVFAIL":
            break
        time.sleep(3)
    addrs = [r for t, r in listed.answers if t == "A"]
    if any(a.startswith("127.255.255.") for a in addrs):
        pytest.skip(
            f"provider-side block (documented error code(s) {addrs}); unverified for CI IPs"
        )
    if listed.rcode == "NXDOMAIN":
        pytest.skip(
            "provider-side: NXDOMAIN for the listed test entry; the Spamhaus FAQ says queries "
            "from public resolvers or IPs with generic rDNS can get 'not listed'"
        )
    if listed.rcode != "NOERROR":
        pytest.skip(f"provider-side failure ({listed.rcode}) while local resolution works")
    assert listed.rcode == "NOERROR", f"documented test entry not listed:\n{listed.raw}"
    assert addrs and set(addrs) <= ZEN_CODES, addrs

    clean = stack.drill(DNSBL_CLEAN_NAME, "A")  # documented "not listed" target
    assert clean.rcode == "NXDOMAIN", clean.raw


# --- exposure and hardening (B, F) -------------------------------------------------------------


def test_nothing_published_on_host(stack: Stack) -> None:
    info = _inspect(stack)
    assert info["HostConfig"]["PortBindings"] in ({}, None)
    ports = info["NetworkSettings"]["Ports"]
    assert all(not v for v in ports.values()), ports  # exposed (5353) but no host binding
    # Host side, via a container in the host's network namespace. Native Linux Docker: the host
    # reaches 172.28.53.2 from the gateway 172.28.53.1, which unbound.conf refuses -> REFUSED.
    # WSL / VM-based Docker: the address is unreachable -> no answer. Either is acceptable;
    # a resolved answer is not. Port 53 must give no answer either.
    for server, port in [(UNBOUND_IP, 5353), (UNBOUND_IP, 53)]:
        try:
            ans = stack.drill("ietf.org", "A", server=server, port=port, network="host")
        except ValueError:
            continue  # no response at all
        assert ans.rcode == "REFUSED", f"host reached {server}:{port}:\n{ans.raw}"
    # Loopback 5353 may legitimately be a host mDNS responder (avahi): it can time out, send
    # garbage, or refuse. Not being published (asserted above) plus "no resolution by Unbound
    # (RA/AD answer)" is the check; REFUSED is not required.
    raw = stack.drill_raw("ietf.org", "A", server="127.0.0.1", port=5353, network="host")
    assert not host_probe_is_unbound(raw), f"host loopback 5353 resolves via Unbound:\n{raw}"


def test_container_hardening(stack: Stack) -> None:
    info = _inspect(stack)
    host = info["HostConfig"]
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"] and not host["CapAdd"]
    assert "no-new-privileges:true" in host["SecurityOpt"]
    assert not host.get("Sysctls")
    assert info["Config"]["User"] == "unbound"


def test_healthcheck_is_healthy(stack: Stack) -> None:
    assert _inspect(stack)["State"]["Health"]["Status"] == "healthy"


# --- app on the dns network (M1-04) ------------------------------------------------------------

# Runs inside the app container with the stdlib only: a minimal UDP DNS query ("." SOA, RD set,
# id 0x1234) to the resolver; any reply carrying the same id proves the path app -> unbound.
_APP_PROBE = (
    "import socket;"
    "q=bytes.fromhex('123401000001000000000000')+b'\\x00'+bytes.fromhex('00060001');"
    "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5);"
    "s.sendto(q,('172.28.53.2',5353));d=s.recv(512);"
    "raise SystemExit(0 if d[:2]==bytes.fromhex('1234') else 1)"
)


def test_app_on_dns_network_reaches_unbound(stack: Stack, monkeypatch: pytest.MonkeyPatch) -> None:
    """With the unbound profile the `app` container is on `dns` and 172.28.53.2:5353 answers."""
    for name in ("SECRET_KEY", "ENCRYPTION_KEY"):  # throwaway, only for this compose project
        monkeypatch.setenv(name, secrets.token_urlsafe(32))
    stack.compose("up", "-d", "--build", "--wait", "--wait-timeout", "120", "app")
    app = f"{stack.project}-app-1"
    nets = json.loads(run("docker", "inspect", app).stdout)[0]["NetworkSettings"]["Networks"]
    assert stack.network in nets, list(nets)
    ip = nets[stack.network]["IPAddress"]
    assert ipaddress.ip_address(ip) in ipaddress.ip_network("172.28.53.128/25"), ip
    run("docker", "exec", app, "python", "-c", _APP_PROBE)
