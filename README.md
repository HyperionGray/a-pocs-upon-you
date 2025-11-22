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

Contents
--------

### Full Exploits

* **[clone_and_pwn](clone_and_pwn/)** - CVE-2018-11235: Git client RCE via malicious submodules
* **[dnsmasq-cve-2017-14493](dnsmasq-cve-2017-14493/)** - CVE-2017-14493: Dnsmasq DHCPv6 RCE
* **[sshtranger_things](sshtranger_things/)** - CVE-2019-6111, CVE-2019-6110: SCP client vulnerabilities

### Advanced Exploit Demonstrations

These exploits demonstrate vulnerabilities with proper protocol implementation and 
sophisticated attack structures. They use benign payloads for research and educational 
purposes.

* **[cve-2024-43639-windows-kerberos](cve-2024-43639-windows-kerberos/)** - CVE-2024-43639: Windows Kerberos KDC Proxy RCE (CVSS 9.8)
  - Proper ASN.1 DER encoding of Kerberos messages
  - Complete KKDCP protocol implementation
  - Integer overflow exploitation theory
  
* **[cve-2024-0012-panos-auth-bypass](cve-2024-0012-panos-auth-bypass/)** - CVE-2024-0012: Palo Alto PAN-OS Authentication Bypass (CVSS 9.8)
  - Fingerprinting and version detection
  - Header manipulation for authentication bypass
  - Read-only API interaction demonstrations
  
* **[cve-2024-49112-windows-ldap](cve-2024-49112-windows-ldap/)** - CVE-2024-49112: Windows LDAP Zero-Click RCE (CVSS 9.8)
  - Proper ASN.1 BER encoding for LDAP
  - Valid bind and search request construction
  - Heap corruption exploitation theory
