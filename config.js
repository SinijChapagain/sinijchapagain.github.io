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
