# HTB Blackfield

**Full Walkthrough:** [walkthrough.md](./walkthrough.md)

**Attack Chain:** User enumeration -> AS-REP Roast -> BloodHound -> Password Reset -> LSASS dump -> Dangerous Privileges -> Domain Admin

---

## Summary

Initial access on Blackfield comes from SMB anonymous/guest enumeration, which allowed me to perform RID bruteforcing to obtain a list of users. With that list, I validated real accounts and identified a user with Kerberos pre-authentication disabled, allowing an AS-REP roast to recover a crackable hash and obtain the first set of domain credentials.

From the foothold, I performed BloodHound enumeration and found delegated rights to reset another user’s password. That pivot grants access to a restricted forensics share containing process memory dumps, including LSASS, which yields higher-privileged credential material. With backup-related privileges (SeBackupPrivilege/Backup Operators), I dumped NTDS.dit and extracted domain hashes, finishing with Administrator via hash-based authentication.

---
