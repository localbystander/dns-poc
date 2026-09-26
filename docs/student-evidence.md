# Student evidence worksheet

Use this alongside the [lab README](../README.md). The transcript below is
**synthetic teaching material**, not a packet capture or proof of a successful
live run. Students without resolver access can analyze it offline and mark the
resolver-side findings in their worksheet as **illustrative only**.

## Collect evidence for your own run

1. Record the run time and time zone, approved resolver address, command, and
   synthetic prompt. Save the script output, for example from PowerShell:

   ```powershell
   python .\dns_oob_lab_v2.py --resolver 10.214.0.2 --workers 1 `
     --prompt "what is the capital of france" 2>&1 | Tee-Object -FilePath .\lab-run.txt
   ```

   Replace the resolver with the instructor-provided address. Start collection
   before running the command so that discovery and the first query are included.

2. If the lab image already includes Wireshark, select the interface carrying
   traffic to that resolver (including a VPN interface if applicable). Use the
   **capture filter** `port 53` to collect both UDP and TCP DNS. Stop after the
   run. Use the **display filter** `dns` to review all DNS destinations, then
   `dns && ip.addr == 10.214.0.2` to focus on the approved IPv4 resolver.
   Save the capture as `lab-client.pcapng`. This is optional: the Python lab has
   no packet-capture dependency. If capture permissions or tooling are absent,
   use instructor-provided evidence or the synthetic transcript below.

3. For one handoff query, expand the DNS question and response. Record QNAME,
   type, source/destination, response code, answer content, TTL, timestamps, and
   UDP/TCP transport. Match request and response using the transaction ID and
   address/port pair. A TXT record can contain several character strings; the
   script joins strings within a record, not across unrelated records.

4. Ask the instructor for matching resolver query/response logs, cache and
   policy decisions, and a resolver-side capture covering outbound port 53.
   Filter that capture by the handoff QNAME and inspect the DNS **Authority**
   section for NS records and **Additional** section for address glue. Correlate
   that address with the next resolver-to-gateway query and returned TXT content.
   A resolver's ordinary client query log may not expose referrals or glue.
   Correlate by QNAME, type, time, and destination: different DNS legs generally
   use different transaction IDs. If your resolver forwards to another resolver,
   the referral and authoritative traffic may only be visible at that upstream
   resolver; document the visibility gap.

5. Use available endpoint/EDR process and network events to associate the
   client exchange with Python. Packet captures alone do not identify processes.
   Because dnspython sends DNS packets itself, an OS DNS-client event source may
   not record the query; process-attributed network events may be needed.

The endpoint capture can establish which resolver it contacted and what reply
it received during the capture window. It cannot reveal the resolver's internal
cache decisions or its upstream referrals. A fast answer or an answer TTL is
not, by itself, proof of cache use. Even a fresh gateway DNS response does not
prove fresh LLM computation; that requires gateway-side evidence.

## Fill in the worksheet

Mark each row **observed**, **not observed**, **not accessible**, or
**illustrative only**. Cite a packet number, log entry, or transcript step.

| Investigation | Observation to record | Evidence source | Interpretation and limitation |
|---|---|---|---|
| Client path | Resolver address, QNAME/type, other DNS destinations, capture window | Client packets and script output | Shows the captured DNS path; does not establish every possible egress restriction |
| Phase A | Public answer, expected encoded address, negative control, egress TXT | Script output and client packets | Cached answers and locally handled `.invalid` negatives do not prove fresh authoritative contact |
| Phase B | ASN(s), IPv4 prefix, hash A/TXT content and statuses | Script output and packets; resolver policy/cache logs | Valid structure supports application exchange; paired NXDOMAIN does not prove registry contact or hash absence |
| Referral | Delegated owner, NS target, glue address | Resolver-side packets | Evidence of the handoff; unavailable from final client replies alone |
| Gateway exchange | Encoded address versus destination, full QNAME, TXT response | Resolver egress packets | Supports DNS delivery to the selected gateway; does not prove fresh computation |
| Response quality | Relevant answer, error text, or empty content | Script output and manual inspection | Nonempty TXT qualifies for the automatic checkpoint even if it is a service error |
| Cache/policy | Hit/miss or policy decision for the exact query | Resolver cache/policy logs | Establishes the resolver's action; gateway caching remains a separate question |
| Process and detection | Python process, matching alert, rule and event time | Endpoint/EDR and detection logs | Packet capture alone lacks process attribution; missing telemetry is not proof of no activity |

Hand in the worksheet, run command/output, and available evidence references.
State what remains unknown. Do not fill missing live evidence using the
illustrative transcript.

## Illustrative transcript — synthetic, not captured

All addresses below are reserved documentation addresses. They do not identify
live services and must not be copied into a live gateway configuration. Times,
IDs, TTLs, content, and the example referral structure are invented to explain
the sequence, not to specify the public service's exact wire format. Root/TLD
lookups, gateway-address discovery, retries, and optional QNAME minimization
are omitted. The hosted service's delegation rules are described at
[nsrecord.net](https://nsrecord.net/).

| Role in this synthetic example | Documentation address |
|---|---|
| Student workstation | `192.0.2.10` |
| Recursive resolver | `192.0.2.53` |
| Handoff authority | `198.51.100.10` |
| DNS gateway | `203.0.113.7` |

In the synthetic transcript, `Q` abbreviates this same complete question on
every leg:

```text
Q = what-is-the-capital-of-france.lab.203-0-113-7.handoff.nsrecord.net. IN TXT
```

```text
SYNTHETIC EXAMPLE — no packets were captured

[1] t=0.000  workstation 192.0.2.10 -> resolver 192.0.2.53
    DNS query ID=0x1001, RD=1, question=Q
    Meaning: the workstation requests recursive resolution.

[2] t=0.020  resolver 192.0.2.53 -> handoff authority 198.51.100.10
    DNS query ID=0x2001, RD=0, question=Q
    Meaning: this example resolver has reached the handoff authority.

[3] t=0.030  handoff authority 198.51.100.10 -> resolver 192.0.2.53
    DNS response ID=0x2001, RCODE=NOERROR, AA=0
    ANSWER: empty
    AUTHORITY (illustrative delegation):
      lab.203-0-113-7.handoff.nsrecord.net. 60 IN NS
        203-0-113-7.handoff.nsrecord.net.
    ADDITIONAL (illustrative address/glue):
      203-0-113-7.handoff.nsrecord.net. 60 IN A 203.0.113.7
    Meaning: this is a referral, not the TXT application answer.

[4] t=0.040  resolver 192.0.2.53 -> gateway 203.0.113.7
    DNS query ID=0x3001, RD=0, question=Q
    Meaning: the destination matches the encoded address and referral address.

[5] t=2.040  gateway 203.0.113.7 -> resolver 192.0.2.53
    DNS response ID=0x3001, RCODE=NOERROR
    ANSWER: Q's owner name, TTL=60, IN TXT "The capital of France is Paris."
    Meaning: text came back in DNS; the delay does not prove new LLM inference.

[6] t=2.050  resolver 192.0.2.53 -> workstation 192.0.2.10
    DNS response ID=0x1001, RCODE=NOERROR, RD=1, RA=1
    ANSWER: Q's owner name, TTL=60, IN TXT "The capital of France is Paris."
    Meaning: the workstation receives a relevant TXT answer through its resolver.

END SYNTHETIC EXAMPLE
```

Only steps 1 and 6 appear in a workstation-side capture. Steps 2–5 require
resolver-side visibility. The referral alone does not prove the gateway was
contacted; step 4 supplies that evidence in this illustration. Neither the
answer nor elapsed time establishes which model produced it or whether it was
newly computed.

### Illustrative cached-response alternative

Suppose the same query is repeated ten seconds after step 6 and the resolver
still holds the answer. An **invented cache-hit variant** would contain a new
client query and an immediate resolver reply with approximately 50 seconds of
TTL remaining. Steps 2–5 would not recur for that lookup. A matching resolver
cache-hit log would support that interpretation. A cached delegation alone can
also omit steps 2–3 while still allowing a fresh step 4; absence of a referral
in one capture is not proof that delegation was never used.

For discussion, replace the example TXT answer with `rate limit exceeded`.
Phase C would still report that TXT content was received; the worksheet should
record that the prompt was not answered. Replace it with whitespace only and
the script should try the next candidate, reporting `NOT OBSERVED` if no
candidate returns nonempty content.
