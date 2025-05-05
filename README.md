# WAF Evasion Techniques & Multi-Stage Testing

![WAF Evasion Techniques](https://media.giphy.com/media/3o6Zt6eq7X8gMX9VYI/giphy.gif)  
*Automated WAF Bypass and Exploitation Framework*

## Key Features

### WAF Evasion Techniques:
- **Unicode escaping**: `\u005f_proto__`
- **Null byte injection**: `prot\u000fotype`
- **Obfuscation**: `__pro__to__`
- **Fake headers**: `X-Forwarded-For spoofing`

### Multi-Stage Testing:
- Basic prototype pollution checks
- WAF bypass payloads
- DOM XSS testing
- RCE attempts (Node.js)
- Privilege escalation

### Smart Detection:
- Auto-detects Cloudflare/Akamai/Imperva
- Polymorphic payload generation
- Response analysis with `jq`

---

## Usage Guide

### Install Dependencies:

```bash
sudo apt update && sudo apt install curl jq nikto sqlmap wfuzz
