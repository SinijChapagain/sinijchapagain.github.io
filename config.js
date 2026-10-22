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
]

if (typeof module !== "undefined" && module.exports) {
  module.exports = { PROFILE, WRITEUPS }
}
