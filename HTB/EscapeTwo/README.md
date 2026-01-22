# HTB EscapeTwo

**Full Walkthrough:** [walkthrough.md](./walkthrough.md)

**Attack Chain**: Assumed Breach Credentials
→ SMB Enumeration
→ Credential Discovery in Broken Excel Workbook
→ MSSQL Access
→ xp_cmdshell Execution
→ Foothold on Host
→ Credential Hunting / Pivot to Domain User
→ BloodHound ACL Discovery
→ WriteOwner → Ownership Takeover on ca_svc
→ Shadow Credentials
→ AD CS Misconfiguration Abuse (ESC4)
→ Domain Administrator Compromise

---

## Summary

EscapeTwo simulates a realistic assume-breach Active Directory environment where initial access begins with limited credentials and escalates through a chain of misconfigurations. After enumerating the environment, I recovered credentials from a broken Excel workbook, which enabled access to MSSQL. From there, I achieved code execution by enabling and using xp_cmdshell, leading to an interactive foothold on the host.

Post-exploitation enumeration revealed an Active Directory access control weakness: the compromised user had WriteOwner privileges over a service account (ca_svc). By taking ownership and modifying permissions, I gained control over the account without resetting its password, opting instead for Shadow Credentials by manipulating msDS-KeyCredentialLink. With access to ca_svc, I was able to exploit an AD CS template misconfiguration (ESC4) to obtain a certificate capable of authenticating as a high-privileged principal, resulting in Domain Administrator compromise.