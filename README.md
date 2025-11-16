A POCs Upon You!
================

This repository contains proof-of-concepts (POCs), exploit code, and other
random or one-off infosec research from [Hyperion
Gray](https://www.hyperiongray.com/?pk_campaign=github&pk_kwd=a-pocs-upon-you)
that is too small to deserve it's own repository.

<a href='https://www.hyperiongray.com/?pk_campaign=github&pk_kwd=a-pocs-upon-you'>
    <img src='https://hyperiongray.s3.amazonaws.com/define-hg.svg'
         alt='define hyperion gray'
         width='75%'></a>

## Exploits

This repository contains POCs for the following vulnerabilities:

### Modern Vulnerabilities (2020+)

- **[Log4Shell (CVE-2021-44228)](log4shell-cve-2021-44228/)** - Critical RCE in Apache Log4j 2, one of the most severe vulnerabilities discovered. Enables remote code execution via JNDI injection.

- **[ProxyShell (CVE-2021-34473)](proxyshell-cve-2021-34473/)** - Microsoft Exchange Server RCE vulnerability chain that allows unauthenticated attackers to execute arbitrary code as SYSTEM.

- **[Spring4Shell (CVE-2022-22965)](spring4shell-cve-2022-22965/)** - Critical RCE in Spring Framework affecting Java 9+ applications, enabling remote code execution via class loader manipulation.

- **[Follina (CVE-2022-30190)](follina-cve-2022-30190/)** - Microsoft Office RCE vulnerability exploiting MSDT, requiring no macros and triggerable by simply opening a document.

### Legacy Vulnerabilities (Pre-2020)

- **[Clone & Pwn (CVE-2018-11235)](clone_and_pwn/)** - Git client RCE via malicious repository with submodules, executes arbitrary code during clone operation.

- **[SSHtranger Things (CVE-2019-6111, CVE-2019-6110)](sshtranger_things/)** - SCP client vulnerability enabling arbitrary file writes during file downloads.

- **[Dnsmasq (CVE-2017-14493)](dnsmasq-cve-2017-14493/)** - Remote code execution in Dnsmasq via malicious DHCPv6 request.

## Usage

Each exploit directory contains:
- **README.md** - Detailed documentation, usage instructions, and mitigation strategies
- **exploit.py** (or similar) - Main exploit script
- **requirements.txt** - Python dependencies (if applicable)

## Security Notice

⚠️ **IMPORTANT**: These exploits are provided for educational and authorized penetration testing purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing any vulnerability.

## Contributing

We welcome contributions of new POCs, especially for modern vulnerabilities that have significant impact. Please ensure:
- The vulnerability is from 2020 or later (for modern exploits)
- It has significant impact (RCE, privilege escalation, memory leaks, etc.)
- Code is well-documented and follows the existing structure
- Include proper attribution and CVE references

## License

Individual exploits may have their own licenses. Please check each directory for specific licensing information.
