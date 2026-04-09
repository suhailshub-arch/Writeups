# Hack Smarter Sysco

**Full Walkthrough**: [walkthrough.md](./walkthrough.md)

**Attack Chain:** Username Enumeration -> AS-REP Roasting -> `jack.downlands` -> Roundcube Access -> Cisco Type 5 Hash Crack -> Password Spray -> `lainey.moore` -> Hardcoded Credentials -> `greg.shields` -> BloodHound Enumeration -> GPO Abuse (`pyGPOAbuse`) -> `john` -> Domain Compromise

## Summary

Initial reconnaissance identified a Windows Active Directory environment exposing several common domain services, along with an externally accessible web server. Enumeration of the public-facing website revealed employee names that were used to generate potential usernames. These usernames were then validated with Kerberos-based enumeration, producing a list of valid domain accounts. From there, AS-REP Roasting identified a vulnerable account, and the recovered hash was cracked to obtain credentials for `jack.downlands`.

Access to the Roundcube webmail instance using `jack.downlands` revealed an email attachment containing a router configuration file. Analysis of the configuration exposed a Cisco Type 5 password hash, which was successfully cracked. The recovered password was then sprayed across the environment and provided valid access as `lainey.moore`, allowing an initial shell to be established via Evil-WinRM.

Further file system enumeration uncovered hard-coded credentials, which were again sprayed across the domain and resulted in access as `greg.shields`. BloodHound analysis then revealed that this user, through membership in **Group Policy Creator Owners**, had control over the **Default Domain Policy** via a **WriteOwner** relationship. Because this GPO was linked to the domain, it could be abused to execute attacker-controlled actions in a privileged context.

Privilege escalation was achieved by abusing the domain-linked GPO with `pyGPOAbuse`, which inserted an immediate scheduled task configured to run as **NT AUTHORITY\SYSTEM**. The payload created the account `john` and granted it administrative privileges. Since the task executed on the domain controller, this resulted in full domain compromise.
