---
name: Bug report
about: Crenel did something wrong (or worse, something silently wrong)
labels: bug
---

<!-- The one unforgivable bug class here is Crenel being SILENTLY wrong about
     exposure (a MISREAD: it reports something false; or a MISMANAGE: a change
     applies/reverts without saying so). If that's what you found, say so loudly.
     If it's a security vulnerability, do NOT file it here. See SECURITY.md §8. -->

**What happened**

**What you expected**

**Repro**
<!-- Ideal: a failing `go test` or a run against the in-repo fakes
     (`-config examples/settings-brownfield.json` etc.), no real infra needed.
     If it needs a real edge, describe the topology instead. -->

```
commands / output here
```

**Environment**
- Crenel version (`crenel version`):
- Edge driver(s) (caddy / traefik / nginx / netbird) + version:
- DNS provider(s) (cloudflare / adguard / dnscontrol), if relevant:
- Transport (direct / ssh-exec / ssh-tunnel):

**Redaction check**
- [ ] I scrubbed real hostnames, IPs, and tokens from everything above
      (use `export --redacted`; never paste a raw config dump, see SECURITY.md)
