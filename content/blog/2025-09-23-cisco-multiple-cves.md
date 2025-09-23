---
title:  "Multiple CVEs in Cisco EPNM and Prime Infrastructure"
description: "During our research activities, we identified multiple vulnerabilities in the web-based management interface of Cisco Evolved Programmable Network Manager (EPNM) and Cisco Prime Infrastructure. These vulnerabilities could allow a remote attacker, who is authenticated and has limited privileges, to execute malicious code on the client side, obtain sensitive information, or upload arbitrary files to a vulnerable system."
authors: ["Paolo Grossetti, Matteo Piciarelli"]
date:   2025-09-23
tags: ["CVE", "Cisco", "EPNM", "Prime-Infrastructure", "Information Disclosure", "Cross-Site Scripting", "Arbitrary File Upload"]
thumbnail:
  url: img/2025-09-23-cisco-multiple-cves/cisco-multiple-cves.jpg
  author: Ideogram
  authorURL: https://ideogram.ai/
---

## Introduction
During our research activities, we identified **multiple vulnerabilities** in the web-based management interface of **Cisco Evolved Programmable Network Manager (EPNM)** and **Cisco Prime Infrastructure**.
The following vulnerabilities have been identified:
- **CVE-2025-20270** – Information Disclosure
- **CVE-2025-20280** – Stored Cross-Site Scripting (XSS)
- **CVE-2025-20287** – Arbitrary File Upload

These vulnerabilities could allow a remote attacker, who is authenticated and has limited privileges, to execute malicious code on the client side, obtain sensitive information, or upload arbitrary files to a vulnerable system. The overall impact of these weaknesses lies in the possibility of compromising the **confidentiality**, **integrity**, and **operational security** of the affected systems.

## CVE-2025-20270

A vulnerability in the web-based management interface of **Cisco Evolved Programmable Network Manager (EPNM)** and **Cisco Prime Infrastructure** could allow an authenticated, remote attacker to obtain **sensitive information** from an affected system.

This issue has been assigned **CVE-2025-20270**.

### Technical description

This vulnerability is due to **improper validation** of requests to API endpoints. An attacker could exploit this vulnerability by sending a valid request to a specific API endpoint within the affected system. A successful exploit could allow a low-privileged user to view sensitive configuration information on the affected system that should be restricted. To exploit this vulnerability, an attacker must have access as a low-privileged user.

- **Type of vulnerability**: Sensitive Information Disclosure   
- **Authentication**: required (low-privileged user)  
- **Impact**: access to sensitive configuration information  
- **Workaround**: not available  
- **Patch**: released by Cisco

### CVSS Score

| Vulnerability  | CVSSv3.1  | Attack Vector |
| --- | --- | --- |
| Information Disclosure | 4.3 | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N/E:X/RL:X/RC:X |

### Affected products
- **Cisco EPNM**: all releases up to 8.1 included  
  - Fixed in: **8.0.1** and **8.1.2**  
- **Cisco Prime Infrastructure**: all releases up to 3.9 and 3.10  
  - Fixed in: **3.10.6 Security Update 02**

### Impact
A successful exploit could allow the attacker to access sensitive configuration data through improperly validated API requests, compromising the confidentiality of the system. While it does not directly affect integrity or availability, the exposure of internal information could facilitate further attacks or unauthorized access.

### Notes
- The vulnerability was discovered in Cisco EPNM 7.1.3
- An authenticated low-privileged user is required  

### Mitigations
Cisco has released software updates that fix this vulnerability. No workarounds exist.  
Administrators should upgrade to a non-vulnerable release, as indicated in the “Fixed Software” section of the official advisory.

### References
- [Cisco Security Advisory – cisco-sa-epnm-info-dis-zhPPMfgz](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-epnm-info-dis-zhPPMfgz)
- [https://www.cve.org/CVERecord?id=CVE-2025-20270](https://www.cve.org/CVERecord?id=CVE-2025-20270)
- [CVE-2025-20270 – NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2025-20270)

## CVE-2025-20280
A vulnerability in the web-based management interface of **Cisco Evolved Programmable Network Manager (EPNM)** and **Cisco Prime Infrastructure** could allow an authenticated, remote attacker to conduct a **stored cross-site scripting (XSS)** attack against users of the interface of an affected system.

This issue has been assigned **CVE-2025-20280**.

### Technical description
This vulnerability exists because the web-based management interface does **not properly validate user-supplied input**. An attacker could exploit this vulnerability by inserting malicious code into specific data fields in the interface. A successful exploit could allow the attacker to execute arbitrary script code in the context of the affected interface or access sensitive, browser-based information. To exploit this vulnerability, an attacker must have valid administrative credentials.

- **Type of vulnerability**: Stored Cross-Site Scripting   
- **Authentication**: required (high-privileged user)  
- **Impact**: potentially lead to session hijacking, data theft, or unauthorized actions performed on behalf of the user without their knowledge   
- **Workaround**: not available  
- **Patch**: released by Cisco

### CVSS Score
| Vulnerability  | CVSSv3.1  | Attack Vector |
| --- | --- | --- |
| Stored Cross-Site Scripting  | 4.8 | AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N/E:X/RL:X/RC:X |

### Affected products
- **Cisco EPNM**: all releases up to 8.0
  - Fixed in: **8.1** 
- **Cisco Prime Infrastructure**: all releases up to 3.9 and 3.10  
  - Fixed in: **3.10.6 Security Update 02**

### Impact
A successful exploit could allow the attacker to inject malicious scripts into the Cisco EPNM or Prime Infrastructure interface, which are then executed in other users' browsers. This compromises both confidentiality and integrity by exposing sensitive data and allowing unauthorized actions, though it does not directly affect system availability.

### Notes
- The vulnerability was discovered in Cisco EPNM 7.1.3
- An authenticated high-privileged user is required 

### Mitigations
Cisco has released software updates that fix this vulnerability. No workarounds exist.  
Administrators should upgrade to a non-vulnerable release, as indicated in the “Fixed Software” section of the official advisory.

### References
- [Cisco Security Advisory – cisco-sa-epnm-pi-stored-xss-XjQZsyCP](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-epnm-pi-stored-xss-XjQZsyCP)
- [https://www.cve.org/CVERecord?id=CVE-2025-20280](https://www.cve.org/CVERecord?id=CVE-2025-20280)
- [CVE-2025-20280 – NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2025-20280)

## CVE-2025-20287
A vulnerability in the web-based management interface of **Cisco Evolved Programmable Network Manager (EPNM)** could allow an authenticated, remote attacker to upload arbitrary files to an affected device.

This issue has been assigned **CVE-2025-20287**.

### Technical description
This vulnerability is due to improper validation of files that are uploaded to the web-based management interface. An attacker could exploit this vulnerability by sending a crafted file upload request to a specific API endpoint. A successful exploit could allow the attacker to **upload arbitrary files** to an affected system. To exploit this vulnerability, an attacker must have at least valid Config Managers credentials on the affected device.

- **Type of vulnerability**: Arbitrary File Upload   
- **Authentication**: required (a valid Config Managers credentials at least)  
- **Impact**: potentially lead to serious consequences such as remote code execution, defacement or complete system compromise, depending on how and where the uploaded files are processed or stored 
- **Workaround**: not available  
- **Patch**: released by Cisco

### CVSS Score
| Vulnerability  | CVSSv3.1  | Attack Vector |
| --- | --- | --- |
| Arbitrary File Upload  | 4.3 | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N/E:X/RL:X/RC:X |

### Affected products
- **Cisco EPNM**: all releases up to 8.0
  - Fixed in: **8.1** 

### Impact
A successful exploit could allow the attacker to upload arbitrary files to the Cisco EPNM system, potentially enabling the placement or execution of unauthorized content. This compromises the integrity of the system by allowing tampering with its file structure, though it does not directly affect confidentiality or availability.

### Notes
- The vulnerability was discovered in Cisco EPNM 7.1.3
- At least a Config Managers credential is required

### Mitigations
Cisco has released software updates that fix this vulnerability. No workarounds exist.  
Administrators should upgrade to a non-vulnerable release, as indicated in the “Fixed Software” section of the official advisory.

### References
- [Cisco Security Advisory – cisco-sa-epni-arb-file-upload-jjdM2P83](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-epni-arb-file-upload-jjdM2P83)
- [https://www.cve.org/CVERecord?id=CVE-2025-20287](https://www.cve.org/CVERecord?id=CVE-2025-20287)
- [CVE-2025-20287 – NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2025-20287)

## Credits
Cisco thanks **Paolo Grossetti** and **Matteo Piciarelli** of Consulthink S.p.A. for responsibly reporting these vulnerabilities.
