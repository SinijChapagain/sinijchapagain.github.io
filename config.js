// Personal Information - Edit this section to update your details
const PERSONAL_INFO = {
  name: "Sinij Chapagain",
  email: "seeneez111@gmail.com",
  phone: "+977 9814915091",
  location: "Nepal",
  bio: "Cybersecurity enthusiast and penetration tester specializing in Active Directory attacks, web application security, and HackTheBox challenges.",
  social: {
    github: "https://github.com/sinijchapagain",
    linkedin: "https://linkedin.com/in/sinijchapagain",
    twitter: "https://twitter.com/sinijchapagain",
    discord: "sinij#1234",
  },
  skills: [
    "Penetration Testing",
    "Active Directory",
    "Web Application Security",
    "Network Security",
    "OSCP Preparation",
    "HackTheBox",
    "Python Scripting",
    "Linux Administration",
  ],
}

// PDF Data - Add new PDFs here
const PDF_DATA = [
  {
    id: 1,
    title: "HackTheBox: Vintage - Windows Active Directory",
    date: "2024-01-15",
    excerpt:
      "Complete walkthrough of the Vintage machine on HackTheBox, covering AS-REP roasting, BloodHound analysis, and Golden Ticket attacks.",
    tags: ["Active Directory", "HTB", "Privilege Escalation"],
    file: "sinijchapagain.github.io/pdfs/Vintage-HTB.pdf",
    difficulty: "Hard",
    category: "Windows",
    markdownFile: "writeups/markdown/vintage-htb.md", // Reference to external markdown file
  },
  // Add more PDFs here as you create them
]

// Tools Data - Add your security tools here
const TOOLS_DATA = [
  {
    name: "Nmap Scanner",
    description: "Advanced port scanning and service enumeration",
    category: "Reconnaissance",
    status: "Coming Soon",
  },
  {
    name: "Hash Cracker",
    description: "Multi-format hash cracking utility",
    category: "Cryptography",
    status: "Coming Soon",
  },
  {
    name: "Payload Generator",
    description: "Custom payload generation for various platforms",
    category: "Exploitation",
    status: "Coming Soon",
  },
]

// Export for use in other files
if (typeof module !== "undefined" && module.exports) {
  module.exports = { PERSONAL_INFO, PDF_DATA, TOOLS_DATA }
}
