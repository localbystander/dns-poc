"""Offline regression tests: all lab replies are synthetic; live DNS is forbidden."""

import contextlib
import io
import unittest
from unittest.mock import patch

import dns_oob_lab_v2 as lab


VALID_ASN = "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
POSITIVE_A = ("NOERROR", ("127.0.0.2",))
POSITIVE_TXT = ("NOERROR", ("1611956489 28",))
NEGATIVE = ("NXDOMAIN", ())
NO_DATA = ("NODATA", ())
ERROR = ("ERROR", ())


class ScriptedClient:
    source = "synthetic test"
    nameservers = ("192.0.2.53",)
    timeout = 1.0

    def __init__(self, replies):
        self.replies = replies
        self.calls = []

    def query(self, qname, qtype="TXT"):
        key = (qname.rstrip("."), qtype)
        self.calls.append(key)
        if key[0].endswith(".invalid"):
            status, answers = NEGATIVE
        else:
            # An unexpected query fails locally; it never falls back to real DNS.
            status, answers = self.replies[key]
        return lab.QueryResult(qname, qtype, status, answers, self.nameservers[0], 0.01)


def baseline_replies(asn=(VALID_ASN,), hash_a=POSITIVE_A, hash_txt=POSITIVE_TXT):
    hash_name = lab.hash_to_cymru_qname(lab.CYMRU_SAMPLE_MD5)
    return {
        ("example.com", "A"): ("NOERROR", ("192.0.2.80",)),
        ("198-51-100-24.sslip.io", "A"): ("NOERROR", ("198.51.100.24",)),
        ("ip.nip.io", "TXT"): ("NOERROR", ("192.0.2.53",)),
        ("8.8.8.8.origin.asn.cymru.com", "TXT"): ("NOERROR", asn),
        ("AS15169.asn.cymru.com", "TXT"): ("NOERROR", ("synthetic description",)),
        (hash_name, "A"): hash_a,
        (hash_name, "TXT"): hash_txt,
    }


def gateway_replies(first="1.1.1.1", second="203.0.113.200"):
    # Address strings only: even non-documentation addresses here are never contacted.
    return {
        (lab.LLM_GATEWAYS[0], "A"): ("NOERROR", (first,)),
        (lab.LLM_GATEWAYS[1], "A"): ("NOERROR", (second,)),
    }


class OfflineTestCase(unittest.TestCase):
    def setUp(self):
        forbidden = patch.object(
            lab.dns.resolver.Resolver,
            "resolve",
            side_effect=AssertionError("Live DNS is forbidden in these tests"),
        )
        self.live_resolve = forbidden.start()
        self.addCleanup(forbidden.stop)
        self.addCleanup(self.live_resolve.assert_not_called)

    def capture(self, function, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = function(*args)
        return result, output.getvalue()


class PhaseBTests(OfflineTestCase):
    def phase(self, **kwargs):
        client = ScriptedClient(baseline_replies(**kwargs))
        result, output = self.capture(lab.phase_b, client, "8.8.8.8", lab.CYMRU_SAMPLE_MD5)
        return result, output, client

    def test_valid_positive_data(self):
        result, output, client = self.phase()
        self.assertIs(result.outcome, lab.PhaseOutcome.OBSERVED)
        self.assertIn("Matching positive hash membership", result.evidence)
        self.assertIn(("AS15169.asn.cymru.com", "TXT"), client.calls)

    def test_multiple_numeric_origin_asns_are_valid(self):
        result, _, client = self.phase(
            asn=("15169 13335 | 8.8.8.0/24 | US | arin | 1992-12-01",)
        )
        self.assertIs(result.outcome, lab.PhaseOutcome.OBSERVED)
        self.assertEqual(sum(name.startswith("AS") for name, _ in client.calls), 1)

    def test_malformed_asn_responses_do_not_count(self):
        for answers in (
            (), ("blocked by policy",), ("",), (" \t",),
            ("15169 | bogus | US | arin | 1992-12-01",),
            ("15169 | 2001:db8::/32 | US | arin | 1992-12-01",),
            ("15169 | 8.8.8.0 | US | arin | 1992-12-01",),
            ("15169 | 8.8.8.8/24 | US | arin | 1992-12-01",),
            ("AS15169 | 8.8.8.0/24 | US | arin | 1992-12-01",),
            ("0 | 8.8.8.0/24 | US | arin | 1992-12-01",),
            ("4294967296 | 8.8.8.0/24 | US | arin | 1992-12-01",),
            ("15169 | 8.8.8.0/24",),
            (VALID_ASN, "blocked by policy"),
        ):
            with self.subTest(answers=answers):
                result, _, client = self.phase(asn=answers)
                self.assertIs(result.outcome, lab.PhaseOutcome.NOT_OBSERVED)
                self.assertFalse(any(name.startswith("AS") for name, _ in client.calls))

    def test_paired_nxdomain_has_explicit_provenance_caveat(self):
        result, output, _ = self.phase(hash_a=NEGATIVE, hash_txt=NEGATIVE)
        self.assertIs(result.outcome, lab.PhaseOutcome.OBSERVED)
        self.assertIn("registry origin and hash absence are unverified", result.evidence)
        self.assertIn("cache or policy", output)
        self.assertNotIn("conclusive hash lookup", output)

    def test_original_policy_text_and_nodata_regression(self):
        result, _, _ = self.phase(
            asn=("blocked by policy",), hash_a=NO_DATA, hash_txt=NO_DATA
        )
        self.assertIs(result.outcome, lab.PhaseOutcome.NOT_OBSERVED)

    def test_nodata_errors_and_contradictory_hash_replies_are_inconclusive(self):
        for hash_a, hash_txt in (
            (NO_DATA, NO_DATA), (NEGATIVE, NO_DATA), (NO_DATA, NEGATIVE),
            (POSITIVE_A, NEGATIVE), (NEGATIVE, POSITIVE_TXT),
            (POSITIVE_A, NO_DATA), (NO_DATA, POSITIVE_TXT),
            (ERROR, ERROR), (ERROR, NEGATIVE),
            (("NOERROR", ("127.0.0.1",)), POSITIVE_TXT),
            (("NOERROR", ("127.0.0.2", "127.0.0.1")), POSITIVE_TXT),
        ):
            with self.subTest(hash_a=hash_a, hash_txt=hash_txt):
                result, _, _ = self.phase(hash_a=hash_a, hash_txt=hash_txt)
                self.assertIs(result.outcome, lab.PhaseOutcome.NOT_OBSERVED)
                self.assertIn("Hash lookup inconclusive", result.evidence)

    def test_malformed_hash_metadata_is_inconclusive(self):
        for answers in (
            (), ("",), (" \t",), ("blocked by policy",),
            ("1611956489",), ("1611956489 28 extra",),
            ("-1 28",), ("1611956489 -1",), ("1611956489 101",),
            ("1611956489 28%",), ("1611956489 28.5",),
            ("1611956489 28", "1611956489 30"),
        ):
            with self.subTest(answers=answers):
                result, _, _ = self.phase(hash_txt=("NOERROR", answers))
                self.assertIs(result.outcome, lab.PhaseOutcome.NOT_OBSERVED)

    def test_hash_percentage_boundaries_and_whitespace(self):
        for metadata in ("0 0", "1611956489 100", " 1611956489\t28 "):
            with self.subTest(metadata=metadata):
                result, _, _ = self.phase(hash_txt=("NOERROR", (metadata,)))
                self.assertIs(result.outcome, lab.PhaseOutcome.OBSERVED)

    def test_asn_description_failure_does_not_change_grade(self):
        replies = baseline_replies()
        replies[("AS15169.asn.cymru.com", "TXT")] = ERROR
        result, _ = self.capture(
            lab.phase_b, ScriptedClient(replies), "8.8.8.8", lab.CYMRU_SAMPLE_MD5
        )
        self.assertIs(result.outcome, lab.PhaseOutcome.OBSERVED)


class PhaseCTests(OfflineTestCase):
    def test_longer_fallback_name_does_not_abort_main_summary(self):
        prompt = "a" * 217
        qname = lab.prompt_to_handoff_qname(prompt, "1.1.1.1")
        self.assertEqual(len(qname), 253)
        replies = baseline_replies()
        replies.update(gateway_replies())
        replies[(qname, "TXT")] = ERROR
        client = ScriptedClient(replies)
        with patch.object(lab, "RecursiveDNSClient", return_value=client):
            exit_code, output = self.capture(lab.main, ["--prompt", prompt])
        self.assertEqual(exit_code, 0)
        self.assertIn("gateway llm.pieter.com: encoding error", output)
        self.assertIn("Capability ladder summary", output)
        self.assertIn("Phase C: NOT OBSERVED", output)

    def test_first_encoding_failure_still_tries_shorter_second_gateway(self):
        prompt = "a" * 217
        replies = gateway_replies(first="203.0.113.200", second="1.1.1.1")
        qname = lab.prompt_to_handoff_qname(prompt, "1.1.1.1")
        replies[(qname, "TXT")] = ("NOERROR", ("synthetic text",))
        client = ScriptedClient(replies)
        result, output = self.capture(lab.phase_c, client, [prompt], 1)
        self.assertIs(result.outcome, lab.PhaseOutcome.OBSERVED)
        self.assertIn("gateway ch.at: encoding error", output)
        self.assertEqual([call for call in client.calls if call[1] == "TXT"], [(qname, "TXT")])

    def test_all_candidates_invalid_still_prints_main_summary(self):
        for prompt in ("a" * 300, "!!!", "你好"):
            with self.subTest(prompt=prompt):
                replies = baseline_replies()
                replies.update(gateway_replies())
                client = ScriptedClient(replies)
                with patch.object(lab, "RecursiveDNSClient", return_value=client):
                    _, output = self.capture(lab.main, ["--prompt", prompt])
                self.assertEqual(output.count("encoding error:"), 2)
                self.assertIn("Capability ladder summary", output)
                self.assertIn("Phase C: NOT OBSERVED", output)
                self.assertFalse(any(name.endswith(lab.HANDOFF_SUFFIX) for name, _ in client.calls))

    def test_blank_txt_triggers_fallback(self):
        prompt = "name a dns record"
        replies = gateway_replies()
        first = lab.prompt_to_handoff_qname(prompt, "1.1.1.1")
        second = lab.prompt_to_handoff_qname(prompt, "203.0.113.200")
        replies[(first, "TXT")] = ("NOERROR", (" \t\n",))
        replies[(second, "TXT")] = ("NOERROR", ("TXT",))
        client = ScriptedClient(replies)
        result, output = self.capture(lab.phase_c, client, [prompt], 1)
        self.assertIs(result.outcome, lab.PhaseOutcome.OBSERVED)
        self.assertIn("whitespace-only TXT", output)
        self.assertIn((second, "TXT"), client.calls)

    def test_all_blank_txt_is_not_observed(self):
        prompt = "name a dns record"
        replies = gateway_replies()
        for address, answer in (("1.1.1.1", ""), ("203.0.113.200", " \t\n")):
            replies[(lab.prompt_to_handoff_qname(prompt, address), "TXT")] = (
                "NOERROR", (answer,)
            )
        result, _ = self.capture(lab.phase_c, ScriptedClient(replies), [prompt], 1)
        self.assertIs(result.outcome, lab.PhaseOutcome.NOT_OBSERVED)

    def test_relevant_and_error_text_both_report_receipt_only(self):
        prompt = "what is the capital of france"
        for answer in ("The capital of France is Paris.", "rate limit exceeded"):
            with self.subTest(answer=answer):
                replies = gateway_replies()
                replies[(lab.prompt_to_handoff_qname(prompt, "1.1.1.1"), "TXT")] = (
                    "NOERROR", (answer,)
                )
                client = ScriptedClient(replies)
                result, output = self.capture(lab.phase_c, client, [prompt], 1)
                self.assertIs(result.outcome, lab.PhaseOutcome.OBSERVED)
                self.assertEqual(result.capability, "TXT response received for a handoff QNAME")
                self.assertIn("delegation, relevance, and fresh computation remain unverified", result.evidence)
                self.assertIn("Review the content for service errors", output)
                self.assertEqual(sum(kind == "TXT" for _, kind in client.calls), 1)

    def test_missing_gateway_addresses_is_not_observed(self):
        replies = {(name, "A"): ERROR for name in lab.LLM_GATEWAYS}
        result, _ = self.capture(lab.phase_c, ScriptedClient(replies), ["hello"], 1)
        self.assertIs(result.outcome, lab.PhaseOutcome.NOT_OBSERVED)


class CLITests(OfflineTestCase):
    def test_help_exits_without_queries(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as caught:
            lab.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        for option in ("--resolver", "--timeout", "--workers", "--lookup-ip", "--hash", "--prompt", "--skip-llm"):
            self.assertIn(option, output.getvalue())

    def test_skip_llm_has_no_gateway_queries(self):
        client = ScriptedClient(baseline_replies())
        with patch.object(lab, "RecursiveDNSClient", return_value=client):
            exit_code, output = self.capture(lab.main, ["--skip-llm"])
        self.assertEqual(exit_code, 0)
        self.assertIn("Phase C: SKIPPED", output)
        self.assertIn("Capability ladder summary", output)
        self.assertFalse(any(name in lab.LLM_GATEWAYS for name, _ in client.calls))


if __name__ == "__main__":
    unittest.main()
