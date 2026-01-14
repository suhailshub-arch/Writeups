# HTB Cicada

**Full Walkthrough:** [walkthrough.md](./walkthrough.md)

**Attack Chain:** SMB Guest Access -> Default Password Disclosure -> RID Brute User Enumeration -> Domain User Foothold -> LDAP Enumeration -> Password Disclosure -> Share Hunting -> Password Disclosure -> Dangerous Privilege Abuse -> NTDS Extraction -> Administrator Compromise

---

## Summary

Initial access was enabled by **SMB Guest logon**, which permitted unauthenticated access to internal shares and domain enumeration. Using Guest access, I discovered an internal file that exposed a **default password for new hires**. I then performed **RID brute enumeration** to build a list of valid domain usernames and validated the leaked password against a domain account to obtain authenticated access.

From the authenticated foothold, further credentials were recovered via **LDAP enumeration** (a password stored in an account description field) and **share hunting** (DEV share containing additional credentials). With valid credentials, I established a **WinRM session** and identified **SeBackupPrivilege** on the compromised account. This privilege was abused to extract high-value credential material, resulting in **Administrator-level compromise**.

---

## Key defensive takeaways

- **Disable SMB Guest access**

- **Eliminate default/shared onboarding passwords**. Enforce unique per-user initial credentials with immediate rotation.

- **Never store secrets in AD attributes** (e.g., user description fields); audit AD regularly for credential-like strings.

- **Harden file share permissions** (least privilege) and continuously scan shares for secrets (secret scanning).

- **Treat `SeBackupPrivilege` as high risk**: restrict assignment and alert on backup-related reads of sensitive hives/databases.

---
