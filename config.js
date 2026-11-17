// Site data - edit this file to update the portfolio without touching the HTML.

const PROFILE = {
  name: "Sinij Chapagain",
  title: "Information Security Specialist",
  email: "seeneez111@gmail.com",
  location: "Kathmandu, Nepal",
  cv: "assets/Sinij_Chapagain_CV.pdf",
  linkedin: "https://www.linkedin.com/in/sinij-chapagain-8588031b0/",
  github: "https://github.com/SinijChapagain",
}

// Writeups - add a markdown file under writeups/markdown/ and an entry here.
// `slug` must match the markdown filename (without .md).
const WRITEUPS = [
  {
    slug: "bad-robot-arkx",
    title: "Bad Robot â Python eval() RCE in an AI Calculator Agent",
    platform: "ARKX Â· AI Agent Security",
    date: "2026-11-16",
    difficulty: "Advanced",
    os: "AI Agent Â· Code Injection",
    excerpt:
      "An AI “calculator” runs user input through Python eval(). Bypassing a substring blocklist with string concatenation and a numeric-only output filter with integer encoding turns a chat box into remote code execution.",
    tags: ["LLM Security", "Prompt Injection", "Python eval()", "RCE", "OWASP LLM01"],
  },
  {
    slug: "master-of-resources-arkx",
    title: "Master of Resources â Broken Access Control in an MCP Server",
    platform: "ARKX Â· AI Agent Security",
    date: "2026-11-16",
    difficulty: "Advanced",
    os: "AI Agent Â· MCP",
    excerpt:
      "An MCP server is fully reachable to any authenticated client and gates its flag behind a caller-invokable unlock_flag tool. Enumerate, flip the lock, read the flag â broken access control at the tool layer.",
    tags: ["LLM Security", "MCP", "Access Control", "Tool Abuse", "OWASP LLM06"],
  },
  {
    slug: "blind-network-ninja-arkx",
    title: "Blind Network Ninja â Blind Command Injection via OOB Exfiltration",
    platform: "ARKX Â· AI Agent Security",
    date: "2026-11-17",
    difficulty: "Advanced",
    os: "AI Agent Â· Command Injection",
    excerpt:
      "A host-uptime agent returns only Online/Offline, but ‘;’ injects shell commands. With output suppressed, the flag is exfiltrated out-of-band through an internal logging endpoint’s query string.",
    tags: ["LLM Security", "Command Injection", "Blind RCE", "OOB Exfiltration", "CWE-78"],
  },
  {
    slug: "gobox-htb",
    title: "GoBox — Go SSTI to Root via S3 and Nginx Module",
    platform: "Hack The Box",
    date: "2025-09-08",
    difficulty: "Hard",
    os: "Linux · Web App",
    excerpt:
      "Go template injection leads to command execution, an uploaded web shell, and a custom nginx module escalation to root — a clean chain from app flaw to full host takeover.",
    tags: ["SSTI", "Go", "Web Shell", "Privilege Escalation", "Nginx"],
  },
  {
    slug: "qlotto-htb",
    title: "QLotto — Exploiting Quantum Lottery Prediction",
    platform: "Hack The Box",
    date: "2025-09-16",
    difficulty: "Medium",
    os: "Linux · Challenge",
    excerpt:
      "A custom quantum challenge where negative-index parsing and entanglement logic let me pivot from “random” output to a deterministic winning strategy.",
    tags: ["Reverse Engineering", "Logic Abuse", "CTF", "Python", "Challenge"],
  },
  {
    slug: "under-construction-htb",
    title: "Under Construction — JWT Confusion + SQLi to Full DB Exfiltration",
    platform: "Hack The Box",
    date: "2025-09-20",
    difficulty: "Hard",
    os: "Linux · Web App",
    excerpt:
      "JWT algorithm confusion is paired with SQL injection to forge a guest token, reach the app DB, and pull the hidden flag from a full database dump path.",
    tags: ["JWT", "Algorithm Confusion", "SQLi", "Web Security", "Auth Bypass"],
  },
  {
    slug: "cicada-htb",
    title: "Cicada — Challenge Notes & Recon Workflow",
    platform: "Hack The Box",
    date: "2025-09-22",
    difficulty: "Research",
    os: "Linux · Enumeration",
    excerpt:
      "A collected set of challenge screenshots and early-stage notes from the Cicada lab, documenting the reconnaissance and exploitation trail as a working writeup draft.",
    tags: ["Recon", "Challenge Notes", "HTB", "Writeup In Progress"],
  },
  {
    slug: "vintage-htb",
    title: "Vintage — Kerberos Delegation to Domain Admin",
    platform: "Hack The Box",
    date: "2025-09-26",
    difficulty: "Hard",
    os: "Windows · Active Directory",
    excerpt:
      "Kerberos-only AD environment with NTLM disabled. Abuses GMSA password reads, group membership, and resource-based constrained delegation, then extracts DPAPI credentials for full domain compromise.",
    tags: ["Active Directory", "Kerberos", "RBCD", "DPAPI", "BloodHound"],
  },
  {
    slug: "crtp-dcorp-domain-admin",
    title: "CRTP — AD Attack Path to Domain Admin",
    platform: "Altered Security · CRTP Lab",
    date: "2025-11-02",
    difficulty: "Lab",
    os: "Windows · Active Directory",
    excerpt:
      "Chaining a Jenkins foothold through GPO abuse, session hunting, overpass-the-hash and DCSync to full forest compromise — written report-style with detection and mitigation guidance at every step.",
    tags: ["Active Directory", "GPO Abuse", "DCSync", "Lateral Movement", "Detection"],
  },
  {
    slug: "kerberos-delegation-defense",
    title: "Kerberos Delegation Abuse — Detection & Defence",
    platform: "Red Team Research",
    date: "2025-10-15",
    difficulty: "Research",
    os: "Active Directory · Blue Team",
    excerpt:
      "A defender-first breakdown of unconstrained, constrained and resource-based delegation: how each is abused, the exact Windows events that expose it, and the controls that shut it down.",
    tags: ["Kerberos", "Delegation", "RBCD", "Blue Team", "Detection Engineering"],
  },
]

if (typeof module !== "undefined" && module.exports) {
  module.exports = { PROFILE, WRITEUPS }
}
