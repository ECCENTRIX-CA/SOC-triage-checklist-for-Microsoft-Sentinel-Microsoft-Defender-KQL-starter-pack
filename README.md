# SOC-triage-checklist-for-Microsoft-Sentinel-Microsoft-Defender-KQL-starter-pack

SOC triage checklist for Microsoft Sentinel + Microsoft Defender (KQL starter pack)
This runbook is a practical, copy/paste-friendly triage flow for SOC analysts and cloud security teams using Microsoft Sentinel and Microsoft Defender XDR. It’s designed to help you go from “new incident fired” to “containment + next actions” fast, without skipping the evidence you’ll need later.

## What’s inside
- A triage workflow you can run in 10–30 minutes depending on severity
- A severity model (P0/P1/P2) with decision points
- Copy/paste checklists for Sentinel + Defender XDR
- A KQL starter pack (common pivots + “first queries”)
A containment-first mindset (stop the bleed, then investigate deeper)

## Scope and assumptions
**Assumes you have:**
- Microsoft Sentinel connected to at least Azure AD / Entra ID sign-in logs and one endpoint signal source
- Defender XDR visibility for endpoints and identities (as available in your environment)

**Not covered (by design):**
- Full threat hunting playbooks
- Forensics deep-dives
- Custom detection engineering (beyond quick validation)

## Severity model (use this to avoid wasting time)

### P0: Active compromise / high confidence malicious
Examples:
- Confirmed malware execution with lateral movement indicators
- Impossible travel + MFA fatigue + suspicious token activity
- Multiple endpoints beaconing / C2 indicators
- Privileged account compromise suspected
  
**Goal:** contain immediately, then preserve evidence.

### P1: Likely malicious, needs fast validation
Examples:
- Suspicious PowerShell + unusual parent process
- Multiple failed logins + successful login from new geo/device
- New OAuth app consent / unusual consent grant
- Suspicious mailbox rule creation

**Goal:** validate quickly, contain if confirmed.

### P2: Low confidence / noisy / informational

Examples:
- Single endpoint alert with weak signal
- Known admin activity (but verify)
- Benign policy triggers

**Goal:** enrich, document, close or tune.

## Triage workflow (10–30 minutes)

### Step 0: Don’t lose the basics (2 minutes)
Copy/paste into your incident notes:
- Incident ID:
- Time detected (UTC/local):
- Alert/Analytics rule name:
- Entities: (user, host, IP, mailbox, app, URL)
- Severity (P0/P1/P2):
- Initial hypothesis (1 sentence):
- Immediate risk: (privileged? widespread? data exfil?)
  
**Decision gate:** If privileged identity or multiple hosts/users are involved → treat as P0/P1 until proven otherwise.

### Step 1: Entity snapshot checklist (5 minutes)
A) User identity (Entra ID / Defender Identity / Defender XDR)
- Is the user privileged? (role membership, admin portals access)
- New device? New geo? New ISP/ASN?
- MFA prompts spike? MFA method changes?
- Risky sign-in / risky user signals?
- Recent password reset? recent token refresh anomalies?
- Recent OAuth consent grants / new app registrations?

B) Host / device (Defender for Endpoint)
- Device risk level / exposure score
- First seen time (new device?)
- Logged-on users (interactive + remote)
- Suspicious processes (PowerShell, rundll32, wscript, mshta, regsvr32)
- Persistence indicators (scheduled tasks, services, run keys)
- Network connections (rare domains, unusual ports, TOR/VPN)

C) IP / network
- Is IP known corporate egress?
-Is it a cloud provider / hosting / suspicious ASN?
- Is it seen across multiple users?
- Geo mismatch vs user baseline?

**Decision gate:** If you see **any** of the following, escalate severity:
- Privileged user + anomalous sign-in
- Multiple endpoints with similar alert pattern
- Evidence of persistence or credential access
- Suspicious OAuth consent / app registration tied to the incident

### Step 2: Containment-first actions (when P0/P1)
Containment is not “panic clicking.” It’s controlled, reversible actions that stop spread.

Identity containment (choose based on confidence)
- Force password reset (if credential compromise suspected)
- Revoke sessions / refresh tokens
- Block sign-in temporarily (P0 only, confirm business impact)
- Require step-up MFA / enforce stronger auth (post-incident hardening)

Endpoint containment
- Isolate device (P0/P1 if active)
- Stop and quarantine file/process (per Defender guidance)
- Collect investigation package (if you have that workflow)

Email containment (if phishing / BEC)
- Remove malicious messages (if available)
- Disable forwarding rules
- Review mailbox rules + recent sign-ins

**Decision gate:** If you cannot confidently contain within 10 minutes, escalate to your incident response owner and document what you observed + what you attempted.

## KQL starter pack — first pivots (Sentinel)
*Notes: table names vary by connector. Use these as patterns and adapt to your workspace schema.* 

1) Find recent sign-ins for a user
`kql
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName =~ "<user@domain.com>"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, ConditionalAccessStatus, Status, DeviceDetail
| order by TimeGenerated desc`

2) Find failed sign-ins followed by success (spray / brute patterns)
`kql
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName =~ "<user@domain.com>"
| summarize
    Failed=countif(Status.errorCode != 0),
    Success=countif(Status.errorCode == 0),
    IPs=makeset(IPAddress, 20)
  by bin(TimeGenerated, 1h), UserPrincipalName
| order by TimeGenerated desc`
3) Check risky sign-ins (if available)
`kql
AADRiskySignins
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "<user@domain.com>"
| project TimeGenerated, UserPrincipalName, RiskLevel, RiskState, RiskEventTypes, IPAddress, Location
| order by TimeGenerated desc`
KQL starter pack — investigation pivots (copy/paste)
4) Pivot from IP address (who else used it?)
`kql
SigninLogs
| where TimeGenerated > ago(7d)
| where IPAddress == "<ip>"
| summarize Users=makeset(UserPrincipalName, 50), Apps=makeset(AppDisplayName, 50), Count=count() by bin(TimeGenerated, 1h), IPAddress
| order by TimeGenerated desc`
5) Conditional Access failures (why was access blocked/allowed?)
`kql
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName =~ "<user@domain.com>"
| project TimeGenerated, AppDisplayName, IPAddress, ConditionalAccessStatus, AuthenticationRequirement, Status, DeviceDetail
| order by TimeGenerated desc`
6) Identify “new device” behavior (rough heuristic)
`kql
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ "<user@domain.com>"
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Count=count() by tostring(DeviceDetail.deviceId), tostring(DeviceDetail.displayName), tostring(DeviceDetail.operatingSystem)
| order by FirstSeen asc`
7) OAuth consent / app registration pivots (common persistence path)
Table names vary; use what your tenant provides (AuditLogs, AADServicePrincipalSignInLogs, etc.)
`kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add application", "Add service principal", "Consent to application", "Add delegated permission grant")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc`
8) Mailbox rule creation (BEC / exfil signal)
`kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| where UserId =~ "<user@domain.com>"
| project TimeGenerated, UserId, Operation, ClientIP, Parameters
| order by TimeGenerated desc`
9) Suspicious forwarding / external sharing indicators (quick scan)
`kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where UserId =~ "<user@domain.com>"
| where Operation has_any ("Set-Mailbox","New-InboxRule","Set-InboxRule")
| project TimeGenerated, UserId, Operation, ClientIP, Parameters
| order by TimeGenerated desc`
10) Endpoint process pivot (Defender for Endpoint advanced hunting)
Use in Defender XDR Advanced Hunting (not Sentinel), unless you’ve ingested MDE tables into Sentinel.
`kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<device>"
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc`
11) Endpoint network connections (beaconing / rare domains)
`kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<device>"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc`
12) File creation / download pivots (payload drop)
`kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<device>"
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc`

## “What do I do next?” The troubleshooting tree (fast decisions)
Use this when you’re stuck in analysis paralysis.
A) Suspicious sign-in / impossible travel / new geo
1. Check sign-in details (app, IP, device, CA result)
2. Check MFA events (fatigue / repeated prompts)
3. Check if user is privileged
4. If suspicious: revoke sessions + reset password + review OAuth consents
5. Post-incident: tighten CA (step-up MFA, device posture lane)

B) Phishing / BEC indicators (mailbox rules, forwarding, consent)
1. Search for mailbox rules changes
2. Check recent sign-ins + IP reuse across users
3. Check OAuth consent/app additions
4. Contain: disable forwarding, revoke sessions, reset creds
5. Hunt: who else got the same message? (if you have telemetry)

C) Endpoint malware / suspicious PowerShell
1. Confirm process tree (parent process, command line)
2. Check network connections (rare domains, suspicious ports)
3. Check persistence (scheduled tasks/services/run keys)
4. Contain: isolate device (P0/P1)
5. Collect evidence package / preserve logs

D) Multiple alerts across many hosts/users (possible campaign)
1. Identify common indicators (IP, URL, hash, sender, rule name)
2. Build a quick KQL query to list all matching entities
3. Contain at the edges: block IP/domain, isolate impacted endpoints, revoke sessions
4. Escalate to incident response owner

## Operational hygiene (keeps your SOC sane)
- Always write a 1–2 sentence “working hypothesis” early, then update it
- Track decisions: what you did, why you did it, and what evidence supported it
- Don’t “close as benign” without stating the evidence that made it benign
- If you add an exception (CA, allowlist, suppression), add an expiry date and owner

## Copy/paste incident notes template (use every time)
Paste this into your ticket / case system:

**Incident summary**
- Incident ID:
- Detection source: (Sentinel analytic rule / Defender alert / other)
- Time detected:
- Severity: (P0/P1/P2)
- Status: (New / Investigating / Contained / Monitoring / Closed)

**Entities**
- User(s):
- Device(s):
- IP(s):
- Mailbox(es):
- App(s):
- URL/Domain(s):
- Hash(es):

**What happened (plain English, 2 to 4 lines)**

**Evidence (bullet points, with timestamps)**

**Actions taken (containment + response)**
- Identity actions: (revoke sessions, reset password, block sign-in, etc.)
- Endpoint actions: (isolate device, quarantine file, etc.)
- Email actions: (remove message, disable forwarding, etc.)
- Network actions: (block IP/domain, etc.)

**Outcome**
- Root cause (if known):
- Impact:
- Follow-ups / hardening tasks:
- Owner + due date:

## KQL pack index (quick navigation)
Use this as your “first 10 queries” list.

**Identity / sign-in pivots (Sentinel)**
- Recent sign-ins for a user (24h)
- Failed vs success sign-ins (spray patterns)
- Risky sign-ins (if available)
- Pivot from IP address (who else used it?)
- Conditional Access outcomes (blocked/allowed + why)
- New device heuristic (first/last seen)

**Email / BEC pivots (Sentinel)**
- Mailbox rule creation/changes
- Forwarding / external sharing indicators (quick scan)

**Endpoint pivots (Defender XDR Advanced Hunting)**
- Suspicious process execution (PowerShell/cmd/mshta/etc.)
- Network connections (rare domains / beaconing)
- File creation / payload drop

*Tip: if you regularly use Defender tables, consider ingesting key MDE signals into Sentinel and standardizing table naming in your workspace docs.*

## Minimal “first response” checklist (printable)
If you only remember one section, use this:
- Identify entities (user, device, IP, mailbox, app)
- Decide severity (P0/P1/P2)
- Snapshot sign-ins + device risk + recent alerts
- Contain if P0/P1 (identity + endpoint)
- Document evidence + actions
- Create follow-ups (CA hardening, detection tuning, user training)
  
## Training paths (for teams implementing this at scale)
If your team is building repeatable SOC triage and response workflows with Microsoft tooling, consider the [SC-200 (Security Operations Analyst)](https://www.eccentrix.ca/en/courses/microsoft/security/microsoft-certified-security-operations-analyst-associate-sc200/) training for Sentinel, Defender detection, investigation, response and/or the [SC-300 (Identity & Access Administrator)](https://www.eccentrix.ca/en/courses/microsoft/security/microsoft-certified-identity-and-access-administrator-associate-sc300/) training for Conditional Access and identity controls that prevent repeat incidents.

## Related readings
[Microsoft Sentinel KQL: A Practical Introduction for Threat Hunting](https://www.eccentrix.ca/en/eccentrix-corner/microsoft-sentinel-kql)
[Threat Intelligence Platform: How Modern Organizations Stay Ahead of Cyber Threats](https://github.com/ECCENTRIX-CA/Threat-Intelligence-Platform-How-Modern-Organizations-Stay-Ahead-of-Cyber-Threats)
[Understanding the Cyber Kill Chain](https://github.com/ECCENTRIX-CA/Understanding-the-Cyber-Kill-Chain)

## License / usage
Use and adapt freely for internal SOC operations. If you publish a derivative, keep the structure and improve it, your future incident responders will thank you.
