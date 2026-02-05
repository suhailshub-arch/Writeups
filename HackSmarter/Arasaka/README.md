# Hack Smarter Arasaka

**Full Walkthrough:** [walkthrough.md](./walkthrough.md)

**Attack Chain:** Faraday Foothold -> Kerberoast -> `alt.svc` -> GenericWrite Abuse (password reset) -> `yorinobu` -> Targeted Kerberoast -> `soulkiller.svc` -> ADCS ESC1 -> Domain Admin

---

## Summary

Initial access began from the **Faraday** foothold, where early **AD enumeration** revealed Kerberos service accounts suitable for Kerberoasting which led to recovering credentials for the service account `alt.svc`.

With `alt.svc`, Bloodhound showed a GenericWrite privilege over another user object. I abused this misconfiguration to perform an account takeover via password change/reset, gaining access as `yorinobu`. From there, I performed a targeted Kerberoast to obtain and crack another service credential, resulting in access as `soulkiller.svc`.

As `soulkiller.svc`, I discovered an **ADCS misconfiguration consistent with ESC1**. By abusing the vulnerable template and using certificate-based authentication, I escalated to **Domain Admin**, completing full domain compromise.

---

## Key defensive takeaways

**Minimize Kerberoast exposure**

- Minimize SPNs, and enforce strong, random, high-entropy passwords for service accounts.

- Monitor for abnormal TGS requests (volume, unusual requester/service combinations).

**Treat ACLs as attack surface**

- Audit AD object permissions (GenericWrite/GenericAll/WriteDACL/WriteOwner) and remove unsafe delegations.

- Alert on suspicious password resets and abnormal modifications to user objects.

---
