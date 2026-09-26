#!/usr/bin/env python3
"""dns_oob_lab_v2.py - zero-infrastructure recursive-DNS lab.

This revision keeps the useful property of the original exercise: the client
only sends ordinary DNS queries to its configured recursive resolver.  The
dynamic work happens at public authoritative DNS services reached through
normal delegation.

Phases:
  A. Resolver/recursion checks and sslip.io input-to-A-record mapping.
  B. Deterministic TXT query APIs from Team Cymru:
       * IP address -> origin ASN and prefix
       * file hash -> malware-registry status
  C. Prompt -> nsrecord.net dynamic NS handoff -> public DNS LLM gateway ->
     TXT response.  The gateway hosts are resolved at runtime, so no account,
     domain, zone configuration, or fixed gateway IP is required.

There is intentionally no arbitrary URL-fetch phase.  The former
``v1.txtify.it`` DNS interface is not available, and no trustworthy public
drop-in replacement was identified.

Install:
    python -m pip install dnspython

Use the operating system's configured resolver (recommended in the lab):
    python dns_oob_lab_v2.py

Use the exercise's internal resolver explicitly:
    python dns_oob_lab_v2.py --resolver 10.214.0.2

Outside the restricted lab, resolver fallback can be demonstrated with:
    python dns_oob_lab_v2.py --resolver 8.8.8.8 --resolver 9.9.9.9

Safety/privacy: DNS is plaintext and commonly logged.  Use synthetic prompts,
public IPs, and public sample hashes only.  Never place credentials, internal
hostnames, customer data, or other secrets in these queries.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import re
import secrets
import sys
import time
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Sequence

import dns.exception
import dns.resolver


DEFAULT_TIMEOUT = 30.0
DEFAULT_WORKERS = 3
HANDOFF_SUFFIX = "handoff.nsrecord.net"
LLM_GATEWAYS = ("ch.at", "llm.pieter.com")

# Public example from Team Cymru's Malware Hash Registry documentation.  It is
# an indicator string only; this script never downloads or executes a sample.
CYMRU_SAMPLE_MD5 = "8a62d103168974fba9c61edab336038c"

DEFAULT_PROMPTS = (
    "what is the capital of france",
    "name three dns record types",
    "explain dns recursion in one sentence",
)


@dataclass(frozen=True)
class QueryResult:
    qname: str
    qtype: str
    status: str
    answers: tuple[str, ...]
    resolver: str
    elapsed: float
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "NOERROR" and bool(self.answers)


class RecursiveDNSClient:
    """Issue queries through one or more recursive resolvers.

    When multiple resolvers are supplied, transient failures such as timeout
    and SERVFAIL move to the next resolver.  Authoritative NXDOMAIN and NODATA
    results are final and are not retried elsewhere.
    """

    def __init__(self, nameservers: Sequence[str] | None, timeout: float):
        self.timeout = timeout

        if nameservers:
            self.nameservers = tuple(self._validate_nameserver(x) for x in nameservers)
            self.source = "explicit"
        else:
            system_resolver = dns.resolver.Resolver(configure=True)
            self.nameservers = tuple(str(x) for x in system_resolver.nameservers)
            self.source = "operating system"

        if not self.nameservers:
            raise RuntimeError("No recursive DNS resolver is configured")

    @staticmethod
    def _validate_nameserver(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError(
                f"Resolver must be an IPv4 or IPv6 address, not {value!r}"
            ) from exc

    def query(self, qname: str, qtype: str = "TXT") -> QueryResult:
        qname = qname.rstrip(".") + "."
        qtype = qtype.upper()
        started = time.monotonic()
        transient_errors: list[str] = []

        for nameserver in self.nameservers:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [nameserver]
            resolver.timeout = min(5.0, self.timeout)
            resolver.lifetime = self.timeout

            try:
                answer = resolver.resolve(
                    qname,
                    qtype,
                    lifetime=self.timeout,
                    search=False,
                )
                values = tuple(self._decode_rdata(item, qtype) for item in answer)
                return QueryResult(
                    qname=qname,
                    qtype=qtype,
                    status="NOERROR",
                    answers=values,
                    resolver=nameserver,
                    elapsed=time.monotonic() - started,
                )
            except dns.resolver.NXDOMAIN as exc:
                return QueryResult(
                    qname=qname,
                    qtype=qtype,
                    status="NXDOMAIN",
                    answers=(),
                    resolver=nameserver,
                    elapsed=time.monotonic() - started,
                    error=str(exc),
                )
            except dns.resolver.NoAnswer as exc:
                return QueryResult(
                    qname=qname,
                    qtype=qtype,
                    status="NODATA",
                    answers=(),
                    resolver=nameserver,
                    elapsed=time.monotonic() - started,
                    error=str(exc),
                )
            except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
                transient_errors.append(
                    f"{nameserver}: {type(exc).__name__}: {exc}"
                )
            except Exception as exc:  # Preserve diagnostics for malformed replies.
                transient_errors.append(
                    f"{nameserver}: {type(exc).__name__}: {exc}"
                )

        return QueryResult(
            qname=qname,
            qtype=qtype,
            status="ERROR",
            answers=(),
            resolver=", ".join(self.nameservers),
            elapsed=time.monotonic() - started,
            error=" | ".join(transient_errors),
        )

    @staticmethod
    def _decode_rdata(item, qtype: str) -> str:
        if qtype == "TXT" and hasattr(item, "strings"):
            # One TXT RDATA may contain several <=255-byte character strings.
            # Joining item.strings reconstructs that record without retaining
            # dnspython's presentation-format quotes and escape sequences.
            return b"".join(item.strings).decode("utf-8", errors="replace").strip()
        return item.to_text()


def print_result(label: str, result: QueryResult) -> None:
    heading = (
        f"{label}: {result.status} via {result.resolver} "
        f"({result.elapsed:.2f}s)"
    )
    print(heading)
    print(f"  query: {result.qname} {result.qtype}")
    if result.answers:
        for value in result.answers:
            lines = value.splitlines() or [""]
            print(f"  answer: {lines[0]}")
            for line in lines[1:]:
                print(f"          {line}")
    elif result.error:
        print(f"  detail: {result.error}")


def ipv4_to_cymru_qname(address: str) -> str:
    ip = ipaddress.ip_address(address)
    if ip.version != 4:
        raise ValueError("The compact lab example currently accepts an IPv4 address")
    return ".".join(reversed(str(ip).split("."))) + ".origin.asn.cymru.com"


def hash_to_cymru_qname(value: str) -> str:
    value = value.lower().strip()
    if not re.fullmatch(r"[0-9a-f]+", value):
        raise ValueError("Hash must contain hexadecimal characters only")
    if len(value) not in (32, 40, 64):
        raise ValueError("Hash must be MD5 (32), SHA-1 (40), or SHA-256 (64 hex chars)")
    if len(value) == 64:
        # A DNS label is limited to 63 octets.  Team Cymru specifies two
        # 32-character labels for SHA-256 values.
        value = value[:32] + "." + value[32:]
    return value + ".hash.cymru.com"


def prompt_to_labels(prompt: str) -> list[str]:
    """Convert a synthetic prompt to one or more DNS-compatible labels."""

    ascii_prompt = (
        unicodedata.normalize("NFKD", prompt)
        .encode("ascii", errors="ignore")
        .decode("ascii")
        .lower()
    )
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_prompt).strip("-")
    if not slug:
        raise ValueError("Prompt has no DNS-compatible characters")

    labels: list[str] = []
    remaining = slug
    while len(remaining) > 63:
        cut = remaining.rfind("-", 0, 64)
        if cut <= 0:
            cut = 63
        labels.append(remaining[:cut].strip("-"))
        remaining = remaining[cut:].strip("-")
    if remaining:
        labels.append(remaining)

    return labels


def prompt_to_handoff_qname(prompt: str, gateway_ip: str) -> str:
    """Build a QNAME that nsrecord.net delegates to a public DNS gateway.

    nsrecord.net delegates names with two or more labels before the embedded
    address.  ``lab`` supplies the second label even for a one-label prompt.
    The selected gateway receives the complete original QNAME as its prompt.
    """

    ip = ipaddress.ip_address(gateway_ip)
    if ip.version != 4:
        raise ValueError("The public handoff demonstration currently uses IPv4")

    encoded_ip = str(ip).replace(".", "-")
    qname = ".".join(
        prompt_to_labels(prompt) + ["lab", encoded_ip, HANDOFF_SUFFIX]
    )
    if len(qname.encode("ascii")) > 253:
        raise ValueError("Encoded prompt exceeds the 253-octet DNS name limit")
    return qname


def phase_a(client: RecursiveDNSClient) -> None:
    print("\n=== Phase A: resolver and recursive reachability ===")
    print_result("A1 known public name", client.query("example.com", "A"))

    negative_name = f"nx-{secrets.token_hex(4)}.invalid"
    print_result(
        "A2 reserved negative control",
        client.query(negative_name, "A"),
    )

    print_result(
        "A3 sslip.io encoded address",
        client.query("198-51-100-24.sslip.io", "A"),
    )

    print_result(
        "A4 authoritative view of recursive egress",
        client.query("ip.nip.io", "TXT"),
    )
    print("  note: A4 normally reports the recursive resolver's source address, not the client")


def phase_b(client: RecursiveDNSClient, lookup_ip: str, file_hash: str) -> None:
    print("\n=== Phase B: deterministic public TXT query services ===")

    asn_result = client.query(ipv4_to_cymru_qname(lookup_ip), "TXT")
    print_result(f"B1 Team Cymru IP-to-ASN ({lookup_ip})", asn_result)

    if asn_result.ok:
        match = re.match(r"\s*(\d+)\s*\|", asn_result.answers[0])
        if match:
            print_result(
                f"B2 Team Cymru ASN details (AS{match.group(1)})",
                client.query(f"AS{match.group(1)}.asn.cymru.com", "TXT"),
            )

    hash_qname = hash_to_cymru_qname(file_hash)
    print_result(
        "B3 Team Cymru malware-hash membership",
        client.query(hash_qname, "A"),
    )
    print_result(
        "B4 Team Cymru malware-hash metadata",
        client.query(hash_qname, "TXT"),
    )
    print("  note: NXDOMAIN for B3/B4 means the hash is absent from the public registry")


def phase_c(
    client: RecursiveDNSClient,
    prompts: Iterable[str],
    workers: int,
) -> None:
    print("\n=== Phase C: dynamic NS handoff to public DNS LLM gateways ===")
    print("Synthetic prompts only: public DNS queries are plaintext, logged, and cacheable.")

    gateways: list[tuple[str, str]] = []
    print("\nGateway discovery through the recursive resolver:")
    for hostname in LLM_GATEWAYS:
        discovery = client.query(hostname, "A")
        print_result(f"C1 gateway {hostname}", discovery)
        for candidate in discovery.answers:
            try:
                parsed = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if parsed.version == 4:
                gateways.append((hostname, str(parsed)))
                break

    if not gateways:
        print("No public DNS LLM gateway address could be resolved; skipping prompts.")
        return

    work: list[tuple[str, str | None]] = []
    for prompt in prompts:
        try:
            # Validate the prompt and full name before starting worker threads.
            prompt_to_handoff_qname(prompt, gateways[0][1])
            work.append((prompt, None))
        except ValueError as exc:
            work.append((prompt, str(exc)))

    def query_prompt(prompt: str):
        attempts: list[tuple[str, QueryResult]] = []
        for hostname, address in gateways:
            qname = prompt_to_handoff_qname(prompt, address)
            result = client.query(qname, "TXT")
            attempts.append((hostname, result))
            if result.ok:
                return hostname, result, attempts
        return gateways[-1][0], attempts[-1][1], attempts

    # Keep concurrency intentionally modest: this is a public hobby/research
    # endpoint, not capacity owned by the lab.
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(query_prompt, prompt) if error is None else None
            for prompt, error in work
        ]

        for index, (prompt, error) in enumerate(work):
            print(f"\nPrompt: {prompt}")
            if error:
                print(f"  encoding error: {error}")
                continue
            hostname, result, attempts = futures[index].result()
            if len(attempts) > 1:
                failed = ", ".join(
                    f"{name}={attempt.status}" for name, attempt in attempts[:-1]
                )
                print(f"  gateway fallback: {failed}")
            print_result(f"C2 delegated LLM through {hostname}", result)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Demonstrate public services reached through recursive DNS only."
    )
    parser.add_argument(
        "--resolver",
        action="append",
        metavar="IP",
        help=(
            "recursive resolver IP; repeat for transient-failure fallback. "
            "Default: operating-system configured resolver(s)"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"per-resolver query lifetime in seconds (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"parallel LLM requests, 1-4 (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--lookup-ip",
        default="8.8.8.8",
        help="public IPv4 address for the Team Cymru lookup (default: 8.8.8.8)",
    )
    parser.add_argument(
        "--hash",
        dest="file_hash",
        default=CYMRU_SAMPLE_MD5,
        help="public MD5/SHA-1/SHA-256 indicator for the malware-hash lookup",
    )
    parser.add_argument(
        "--prompt",
        action="append",
        help="synthetic LLM prompt; repeat for several prompts",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="run deterministic DNS phases only",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if not 1 <= args.workers <= 4:
        parser.error("--workers must be between 1 and 4")

    try:
        # Validate user-controlled indicators before sending any DNS query.
        ipv4_to_cymru_qname(args.lookup_ip)
        hash_to_cymru_qname(args.file_hash)
        client = RecursiveDNSClient(args.resolver, args.timeout)
    except (RuntimeError, ValueError) as exc:
        parser.error(str(exc))

    print("Recursive DNS public-service lab v2")
    print(f"Resolver source: {client.source}")
    print(f"Resolvers: {', '.join(client.nameservers)}")
    print(f"Per-resolver lifetime: {client.timeout:g}s")
    print("No direct HTTP requests are made by this client.")

    phase_a(client)
    phase_b(client, args.lookup_ip, args.file_hash)

    if args.skip_llm:
        print("\nLLM phase skipped by request.")
    else:
        phase_c(client, args.prompt or DEFAULT_PROMPTS, args.workers)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
