# Test fixtures

Every file here is **synthetic and hand-written** for tests. Brands, domains, IDs, IPs and
certificates are fictional. Nothing was captured from a live site, and tests never make real
network or DNS requests.

| Folder | Contents |
|---|---|
| `html/` | `kit_a.html` and `kit_b.html` are two copies of the same fake phishing kit (same markup, different wording). `unrelated.html` is an ordinary blog page. `tiny.html` is a near-empty error page. |
| `favicons/` | `kit.ico`: a small icon file. |
| `dns/answers.json` | Saved DNS answers (name → record type → values), served by `FakeDnsResolver`. |
| `rdap/` | RDAP domain responses in the format registries return. |
| `crtsh/` | crt.sh JSON search results, including a precertificate/certificate pair. |
