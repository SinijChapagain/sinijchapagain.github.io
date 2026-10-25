# Kerberos Delegation Abuse — Detection & Defence

> Delegation is one of the most abused — and least understood — corners of Active Directory. I've exploited all three variants on lab AD boxes (Vintage, the CRTP forest) and I've had to defend against them in production banking environments. This is a defender-first breakdown: what each delegation type is, how it's abused, and the concrete controls and log signals that stop it.

## Why delegation exists

Delegation lets a service act *on behalf of* a user to reach a back-end resource — the classic "web server queries a database as the logged-in user" problem. Useful, but it means a service holds the keys to impersonate others, and misconfiguration turns that into privilege escalation.

## The three flavours

### 1. Unconstrained delegation (worst)
A host trusted for unconstrained delegation caches the **TGT of every user** who authenticates to it. Compromise that host and you can extract and reuse those TGTs — including a Domain Admin's, or even a Domain Controller's computer account if you can coerce it to authenticate (e.g. the printer-bug / `PrinterBug`).

- **Abuse:** extract cached TGTs → impersonate anyone who touched the host.
- **Defend:** eliminate unconstrained delegation entirely where possible. Mark sensitive accounts **"Account is sensitive and cannot be delegated"** (or add them to **Protected Users**). Audit with `Get-ADComputer -Filter {TrustedForDelegation -eq $true}`.

### 2. Constrained delegation
The account may only delegate to a **named list of SPNs** (`msDS-AllowedToDelegateTo`). But **protocol transition** (`TrustedToAuthForDelegation`) lets it request tickets *as any user* to those services via `S4U2Self` + `S4U2Proxy`.

- **Abuse:** if you own a constrained-delegation account, forge service tickets as a privileged user to the allowed SPNs. The SPN's service class can often be swapped (e.g. `HTTP` → `CIFS`), widening impact.
- **Defend:** prefer constrained delegation *without* protocol transition ("Kerberos only"); tightly control who holds `msDS-AllowedToDelegateTo`; monitor **S4U** ticket requests.

### 3. Resource-Based Constrained Delegation (RBCD)
The trust is configured on the **target** resource via `msDS-AllowedToActOnBehalfOfOtherIdentity`. If you can **write that attribute** on a computer object (e.g. you have a machine-account quota and `GenericWrite`/`WriteDACL` over the target), you set up delegation *to yourself* and impersonate any user — including a local admin — to that machine. This is the path I used on **Vintage**.

- **Abuse:** create/control a computer account → set RBCD on the target → `S4U` impersonate a privileged user → full access.
- **Defend:** set **`ms-DS-MachineAccountQuota = 0`** so ordinary users can't add computer accounts; audit write access to computer objects; alert on changes to `msDS-AllowedToActOnBehalfOfOtherIdentity`.

## What to watch in the logs

| Signal | Event / Source | Why it matters |
|---|---|---|
| TGS requests with S4U | **4769** (ticket granting) | Delegation impersonation leaves S4U2Self/S4U2Proxy traces |
| Write to delegation attributes | **5136** (directory object modified) | RBCD and constrained-delegation setup |
| New computer account | **4741** | Precedes many RBCD attacks |
| Replication from non-DC | **4662** (DRSUAPI GUIDs) | The post-exploitation payoff — DCSync |
| TGT reuse / anomalous lifetime | Kerberos ticket analytics | Unconstrained-delegation TGT theft, Golden Tickets |

## A defender's checklist

1. **Inventory delegation.** Enumerate every account with any delegation flag set — most orgs have forgotten ones.
2. **Protect the crown jewels.** Domain Admins and other tier-0 accounts → *sensitive, cannot be delegated* + Protected Users.
3. **Kill `MachineAccountQuota`.** Set it to 0 unless there's a real reason not to.
4. **Prefer constrained, Kerberos-only.** No unconstrained delegation; no protocol transition unless unavoidable.
5. **Detect, don't just prevent.** S4U patterns, delegation-attribute writes, and non-DC replication are high-fidelity alerts.

Delegation abuse is powerful precisely because the primitives are *legitimate Kerberos features*. You rarely stop it with a single control — you stop it by removing unnecessary delegation, protecting privileged identities, and instrumenting the handful of events that attackers can't avoid generating.
