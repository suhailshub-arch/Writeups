# HTB — Sauna (Retired)

> **Mini Pentest Report (PDF):** [Sauna-Pentest-Report.pdf](TODO)  
> **Full Walkthrough (technical):** [walkthrough.md](./walkthrough.md)

**Attack chain:** Website OSINT → Username enumeration → AS-REP Roasting → WinRM foothold → AutoLogon creds → BloodHound path → DCSync → Domain Admin

**Skills demonstrated:** AD enumeration, Kerberos abuse (AS-REP Roasting), WinRM post-exploitation, credential discovery (AutoLogon), BloodHound privilege path analysis, DCSync domain escalation, remediation-focused reporting.

---

## Summary

- Started from passive recon against the public website to collect employee names.
- Generated likely usernames and validated them with Kerberos enumeration.
- AS-REP Roasting produced offline-crackable material; used recovered creds for a WinRM foothold as a domain account.
- Host enumeration revealed AutoLogon credentials enabling lateral movement to a service account which held higher privileges.
- BloodHound identified a viable privilege path; DCSync via `secretsdump.py` led to Domain Admin access.

---

## Evidence

> Screenshots are redacted. Stored under `./Evidence/`.

1. Website employee names (OSINT)  
   ![Website OSINT](./Evidence/webpage_about.png)

2. Kerberos user enumeration (valid users)  
   ![Kerbrute enum](./Evidence/kerbrute_output.png)

3. AS-REP roast proof (hash redacted)  
   ![AS-REP roast](./Evidence/ASREPRoast%20Output.png)

4. WinRM foothold as domain user  
   ![WinRM foothold](./Evidence/nxc_winrm_fsmith_output.png)

5. AutoLogon credential discovery
   ![AutoLogon creds](./Evidence/AutoLogon_Creds.png)

6. BloodHound path to DCSync  
   ![BloodHound path](./Evidence/Bloodhound%20Path.png)

7. DCSync proof (redacted) / DA access proof  
   ![DCSync proof](./Evidence/secretdump_admin.png)

---

## Key defensive takeaways

- Enforce **Kerberos pre-authentication** across the domain (prevents AS-REP roasting).
- Require strong user passwords (>14 characters in length and limit common word usage)
- Remove **AutoLogon** and stop storing plaintext secrets in registry.
- Audit and restrict **directory replication permissions** (prevents DCSync / domain takeover).

---

## Repo contents

- **[Sauna-Pentest-Report.pdf](./Sauna-Pentest-Report.pdf)** — Deliverable-style report.
- **[walkthrough.md](./walkthrough.md)** — Full Walkthrough
- `./Evidence/` — screenshots referenced above.
