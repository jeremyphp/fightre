# Signal catalogue

Generated from `fightre/signals.py` - do not edit by hand. Regenerate with:

```bash
python tools/gen_signals_doc.py
```

Weights are evidence probabilities in `0..100`; the scoring engine combines them
with a noisy-OR. A `hard-block` marker means the signal is decisive on its own
and bypasses the score bands.

| signal | layer | weight | hard-block | description |
| --- | --- | --- | --- | --- |
| `net.datacenter_asn` | L1-network | 22 |  | Client IP belongs to a datacenter/hosting ASN |
| `net.geo_mismatch` | L1-network | 14 |  | Accept-Language region disagrees with IP geolocation |
| `net.proxy_or_vpn` | L1-network | 28 |  | Client IP is a known commercial proxy or VPN exit |
| `net.rate_burst` | L1-network | 35 |  | Request rate exceeded the per-identity budget |
| `net.scanner_pattern` | L1-network | 42 |  | Sequential path probing typical of a scanner |
| `net.tor_exit` | L1-network | 50 |  | Client IP is a Tor exit node |
| `proto.accept_encoding_mismatch` | L2-protocol | 8 |  | Modern browser claim without the compression it always offers |
| `proto.agent_runtime` | L2-protocol | 50 |  | Automation / RE-agent runtime markers (Playwright, CDP bridge, Frida helper) |
| `proto.bot_user_agent` | L2-protocol | 40 |  | User-Agent announces a scripting HTTP client |
| `proto.duplicate_header` | L2-protocol | 12 |  | Duplicate singleton header (possible proxy or rewriter) |
| `proto.edge_signature_invalid` | L2-protocol | 70 | yes | Edge-injected fingerprint headers were not signed by the edge |
| `proto.h2_fingerprint_anomaly` | L2-protocol | 26 |  | HTTP/2 SETTINGS fingerprint deviates from the claimed client |
| `proto.header_order_anomaly` | L2-protocol | 14 |  | Header ordering deviates from the claimed browser engine |
| `proto.ja3_known_bot` | L2-protocol | 50 |  | TLS ClientHello fingerprint matches a known automation stack |
| `proto.missing_browser_headers` | L2-protocol | 16 |  | A browser User-Agent without the headers that browser always sends |
| `proto.smuggling_probe` | L2-protocol | 55 | yes | Both Content-Length and Transfer-Encoding present |
| `proto.ua_client_hints_mismatch` | L2-protocol | 28 |  | User-Agent version/brand contradicts sec-ch-ua hints |
| `client.attestation_forged` | L3-client | 75 | yes | Attestation signature invalid or replayed |
| `client.cdp_runtime_leak` | L3-client | 50 |  | Chrome DevTools Protocol artefacts leaked into the page |
| `client.devtools_open` | L3-client | 8 |  | DevTools appears to be open (weak, humans do this too) |
| `client.env_anomaly` | L3-client | 18 |  | Client environment has an unusual but non-decisive property |
| `client.function_tostring_patched` | L3-client | 42 |  | Native functions were monkey-patched (hook injection) |
| `client.headless_ua` | L3-client | 45 |  | User-Agent contains a headless/automation marker |
| `client.honeypot_clicked` | L3-client | 55 |  | Invisible honeypot field was filled by the client |
| `client.missing_attestation` | L3-client | 16 |  | Browser claim without a valid FightRE attestation |
| `client.signal_inconsistency` | L3-client | 36 |  | Client environment signals contradict each other |
| `client.software_renderer` | L3-client | 30 |  | WebGL renderer is a software rasterizer (SwiftShader/llvmpipe) |
| `client.stale_attestation` | L3-client | 20 |  | Attestation older than the freshness window |
| `client.webdriver` | L3-client | 55 |  | navigator.webdriver is set (automation driver attached) |
| `app.bad_signature` | L4-app | 60 | yes | Request signature did not verify |
| `app.bulk_export` | L4-app | 40 |  | Bulk export shape requested by an unverified identity |
| `app.decoy_schema_access` | L4-app | 70 |  | Honey-schema endpoint used: the client is consuming poisoned evidence |
| `app.enumeration_pattern` | L4-app | 32 |  | Sequential identifier enumeration detected |
| `app.honeypot_endpoint` | L4-app | 85 |  | Request hit a decoy endpoint that no real client links to |
| `app.introspection_probe` | L4-app | 34 |  | API schema introspection requested (OpenAPI, Swagger, GraphQL __schema) |
| `app.missing_signature` | L4-app | 22 |  | Signed endpoint called without a signature |
| `app.payload_tamper` | L4-app | 45 |  | Payload hash disagreees with the signature binding |
| `app.rate_limit` | L4-app | 30 |  | Application-level quota exceeded |
| `app.replay_detected` | L4-app | 70 | yes | Signed request replayed (nonce reuse) |
| `app.sequence_scan` | L4-app | 30 |  | Rapid traversal of many distinct paths by one identity |
| `app.source_artifact_probe` | L4-app | 40 |  | Build artefact requested (source map, .git, ASAR, backup file) |
| `app.timestamp_skew` | L4-app | 35 |  | Signature timestamp outside the tolerated clock skew |
| `data.bulk_scan` | L5-data | 28 |  | Response paging pattern consistent with dataset scraping |
| `data.canary_accessed` | L5-data | 70 | yes | A canary token was read and re-submitted to the service |
| `data.canary_echo` | L5-data | 65 | yes | A FightRE canary token was sent back to the service |
| `data.field_tamper` | L5-data | 38 |  | Client-side field integrity check failed |
| `data.watermark_leak` | L5-data | 60 | yes | Leaked document carries our zero-width watermark |

_47 signals across 5 layers._
