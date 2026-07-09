---
name: Feature request
about: A verb, driver, or topology Crenel should handle
labels: enhancement
---

**The problem, in operator terms**
<!-- What are you trying to expose/unexpose/verify, on what stack? -->

**What Crenel does today**
<!-- Include `status`/`audit` output if it declares your construct unknown;
     "declared unknown" vs "misread" matters a lot here. Check
     ../../docs/internal/TOPOLOGY-RISK-REGISTER.md and docs/security/KNOWN-LIMITS.md first:
     if it's listed there, this is a request to extend a known boundary. -->

**What you'd want it to do**

**Invariant check** (the bars any feature must clear; see CONTRIBUTING.md)
- [ ] Keeps default-deny structural (an unexposed host stays unreachable)
- [ ] Keeps bounded honesty (anything unparseable stays declared, never guessed)
- [ ] Mutations read-back-verify against the live edge
