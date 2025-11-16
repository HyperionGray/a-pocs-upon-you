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

### Modern Vulnerabilities (2020+)

#### [PHP CGI Argument Injection (CVE-2024-4577)](php-cgi-cve-2024-4577/)
Critical remote code execution vulnerability in PHP's CGI implementation on Windows systems.
Allows attackers to execute arbitrary PHP code via argument injection through URL-encoded
soft hyphen characters.
- **Severity**: Critical (CVSS 9.8)
- **Affected**: PHP 8.3 < 8.3.8, PHP 8.2 < 8.2.20, PHP 8.1 < 8.1.29

#### [Log4Shell (CVE-2021-44228)](log4shell-cve-2021-44228/)
One of the most critical vulnerabilities in recent history. Allows unauthenticated remote
code execution in applications using Apache Log4j 2 through JNDI injection.
- **Severity**: Critical (CVSS 10.0)
- **Affected**: Apache Log4j 2.0-beta9 through 2.14.1

#### [Spring4Shell (CVE-2022-22965)](spring4shell-cve-2022-22965/)
Remote code execution vulnerability in Spring Framework affecting applications deployed
as WAR files on Apache Tomcat. Exploits data binding to write malicious JSP webshells.
- **Severity**: Critical (CVSS 9.8)
- **Affected**: Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19

### Legacy Vulnerabilities

#### [Clone & Pwn (CVE-2018-11235)](clone_and_pwn/)
Git client vulnerability that executes arbitrary code when cloning a malicious repository
with the `--recurse-submodules` flag.

#### [Dnsmasq (CVE-2017-14493)](dnsmasq-cve-2017-14493/)
Remote code execution in Dnsmasq via DHCPv6 request.

#### [SSHtranger Things (CVE-2019-6111, CVE-2019-6110)](sshtranger_things/)
SCP client vulnerabilities allowing arbitrary file writes and display manipulation.
