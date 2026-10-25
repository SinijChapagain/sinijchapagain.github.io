# CRTP — Active Directory Attack Path to Domain Admin

> A walkthrough of the enterprise attack path I worked through while preparing for the **Certified Red Team Operator** material, inside the lab Active Directory forest (`dcorp.local`). It chains a foothold on a CI server all the way to a full forest compromise. I've written it the way I write a red-team report: what the step was, *why* it worked, and — most importantly for a defender — **how to detect and stop it**.
>
> This is a training-lab environment. No exam content is reproduced here; everything below is standard, publicly documented Active Directory tradecraft.

## The path at a glance

```
Jenkins (DCORP-CI)  ──▶  ciadmin on DCORP-CI
      │
      ▼  overly-permissive GPO abuse
local admin on DCORP-CI  ──▶  session hunting
      │
      ▼  Domain Admin session found on DCORP-MGMT
dump creds (svcadmin = Domain Admin)
      │
      ▼  overpass-the-hash
Domain Admin  ──▶  WinRM to the DC  ──▶  DCSync krbtgt
      │
      ▼
Golden Ticket / full forest persistence
```

## 1. Foothold — Jenkins to code execution

The entry point is an exposed **Jenkins** instance with weak access control. Jenkins' build/script console runs commands as the service account (`ciadmin`) on `DCORP-CI`. Dropping a short Groovy script into the script console gives command execution in the context of that service account.

**Why it works:** CI/CD systems routinely run as privileged service identities and are often left reachable with default or missing authentication. They are a classic initial-access pivot.

**Detect / defend:** require authentication on Jenkins, disable the script console for non-admins, run build agents as low-privilege accounts, and alert on unexpected child processes spawned by the Jenkins service.

## 2. Local privilege escalation — GPO abuse

From `ciadmin`, enumeration (BloodHound + PowerView) surfaced an **overly permissive Group Policy Object** that could be edited by a non-privileged principal. Abusing write access to that GPO, a controlled user was added to the local Administrators group on `DCORP-CI`.

**Why it works:** `GpLink` + `WriteDACL`/`WriteProperty` edges on a GPO let an attacker push a local-group-membership or scheduled-task change to every machine the GPO applies to.

**Detect / defend:** audit GPO permissions (Event ID **5136** — directory object modified), restrict who can edit GPOs, and review BloodHound `GPO` control edges as part of AD hygiene.

## 3. Lateral movement — session hunting

As a local admin, I enumerated logon sessions across the estate (`Invoke-SessionHunter` / `Find-DomainUserLocation`). This revealed an active session for **`svcadmin`** — a Domain Admin — on `DCORP-MGMT`.

**Why it works:** privileged accounts logging on interactively to member servers leave credential material in LSASS. Finding *where* privileged users are logged in is the whole game in AD lateral movement.

**Detect / defend:** enforce the **tiered administration model** — Domain Admins never log on to tier-1/tier-2 hosts. Use LAPS for local admin passwords and monitor for session-enumeration behaviour (mass `NetSessionEnum` / `NetWkstaUserEnum`).

## 4. Credential theft — Domain Admin

With admin rights on `DCORP-MGMT` and a DA session present, LSASS credential extraction yielded `svcadmin`'s secrets.

**Why it works:** interactive and RunAs logons cache credentials in memory. Admin on the box = credentials of everyone logged into it.

**Detect / defend:** enable **Credential Guard**, restrict debug/`SeDebugPrivilege`, deploy an EDR that protects LSASS, and treat any LSASS access by a non-security process as high severity.

## 5. Domain compromise — overpass-the-hash + DCSync

Using `svcadmin`'s hash, **overpass-the-hash** produced a valid Kerberos TGT, which authenticated a WinRM session to the domain controller. From the DC, a **DCSync** (directory-replication) request extracted the **`krbtgt`** hash.

**Why it works:** any principal with the *Replicating Directory Changes* rights (Domain Admins have them) can ask the DC to hand over password hashes via `DRSUAPI` — no code needs to run on the DC itself.

**Detect / defend:** alert on `DRSUAPI` replication (**Event ID 4662** with the replication GUIDs) from any host that isn't a DC; this is one of the single highest-value detections in an AD environment.

## 6. Persistence — the Golden Ticket

With the `krbtgt` hash, an attacker can forge **Golden Tickets** — arbitrary TGTs for any user, valid until `krbtgt` is rotated **twice**. This is why `krbtgt` is the crown-jewel secret of a domain.

**Detect / defend:** rotate `krbtgt` twice on any suspected compromise, monitor for TGTs with anomalous lifetimes, and watch for tickets referencing non-existent or privileged accounts.

## Takeaways for defenders

- **CI/CD is production.** A Jenkins box running as a domain-joined service account is a domain foothold.
- **GPO ACLs are attack surface.** Treat GPO edit rights like Domain Admin.
- **Tiering beats everything.** Most of this path collapses if Domain Admins never touch member servers.
- **DCSync detection is non-negotiable.** Replication from a non-DC is a reliable, high-fidelity signal of domain compromise.

*Tools referenced: PowerView, BloodHound, Rubeus, Mimikatz-class credential tooling, and native Windows replication APIs — all standard in authorized red-team engagements.*
