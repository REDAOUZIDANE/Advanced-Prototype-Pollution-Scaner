#!/bin/bash

# ASCII Art
echo -e "\e[1;31m
   ____  ____   ____    _   _ _____ _   _ ______ _____  
  |  _ \|  _ \ / __ \  | \ | |  __ \ | | |  ____|  __ \ 
  | |_) | |_) | |  | | |  \| | |  | | | | |__  | |__) |
  |  __/|  __/| |  | | | . \ | |  | | | |  __| |  _  / 
  | |   | |   | |__| | | |\  | |__| | |_| |____| | \ \ 
  |_|   |_|    \____/  |_| \_|_____/ \___/______|_|  \_\\
  \e[0m"
echo -e "\e[1;34mJS-Lib-Pwner v2.0 - JavaScript Library Vulnerability Scanner\e[0m"
echo -e "\e[1;33mBy Reda Ouzidane (0xf14) \e[0m"
echo -e "\e[1;32m----------------------------------------\e[0m\n"

# Check if URL is provided
if [ -z "$1" ]; then
    echo -e "\e[1;31m[!] Usage: $0 <target_url> [--exploit]\e[0m"
    echo -e "\e[1;36mExample: $0 https://example.com\e[0m"
    echo -e "\e[1;36mDeep Scan: $0 https://example.com --exploit\e[0m"
    exit 1
fi

TARGET="$1"
OUTPUT_DIR="js_scan_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

# List of JS libraries to check
declare -A JS_LIBRARIES=(
    ["jQuery"]="jquery"
    ["Lodash"]="lodash"
    ["core-js"]="core-js"
    ["Swiper"]="swiper"
    ["lit-html"]="lit-html"
    ["Goober"]="goober"
    ["Boomerang"]="boomerang"
)

# Known vulnerable versions
declare -A VULN_VERSIONS=(
    ["jQuery"]="<3.5.0"
    ["Lodash"]="<4.17.21"
    ["core-js"]="<3.8.0"
    ["Swiper"]="<6.0.0"
    ["lit-html"]="<2.0.0"
    ["Goober"]="<2.0.0"
    ["Boomerang"]="<1.0.0"
)

# CVE database (simplified)
declare -A CVE_DB=(
    ["jQuery<3.5.0"]="CVE-2020-11022,CVE-2020-11023"
    ["Lodash<4.17.15"]="CVE-2020-8203"
    ["core-js<3.8.0"]="CVE-2020-11042"
    ["Swiper<5.4.5"]="CVE-2020-7650"
)

# Fetch JavaScript files from target
fetch_js_files() {
    echo -e "\e[1;34m\n[+] Fetching JavaScript files from $TARGET...\e[0m"
    curl -s "$TARGET" | grep -Eo 'src="[^"]*\.js"' | cut -d'"' -f2 | sort -u > "$OUTPUT_DIR/js_files.txt"
    
    # Handle relative paths
    sed -i "s|^/|$TARGET/|" "$OUTPUT_DIR/js_files.txt"
    sed -i "/^http/! s|^|$TARGET/|" "$OUTPUT_DIR/js_files.txt"
    
    echo "Found $(wc -l < "$OUTPUT_DIR/js_files.txt") JS files"
}

# Check for vulnerable libraries
check_libraries() {
    echo -e "\e[1;34m\n[+] Checking for vulnerable JavaScript libraries...\e[0m"
    
    while read -r js_file; do
        echo -e "\n\e[1;33mAnalyzing $js_file\e[0m"
        content=$(curl -s "$js_file")
        
        for lib in "${!JS_LIBRARIES[@]}"; do
            pattern="${JS_LIBRARIES[$lib]}"
            if grep -qi "$pattern" <<< "$content"; then
                version=$(grep -Eio "$pattern.*v?[0-9.]+" <<< "$content" | grep -Eo "[0-9.]+" | head -n1)
                echo -e "\e[1;32m[+] Found $lib version $version\e[0m"
                
                # Check if version is vulnerable
                vuln_ver="${VULN_VERSIONS[$lib]}"
                if [[ "$version" != "" && "$vuln_ver" != "" ]]; then
                    if [[ "$vuln_ver" =~ ^\<.*$ ]]; then
                        max_safe=$(echo "$vuln_ver" | tr -d '<')
                        if [[ "$(printf '%s\n' "$version" "$max_safe" | sort -V | head -n1)" != "$max_safe" ]]; then
                            echo -e "\e[1;31m[!] VULNERABLE: $lib $version (Vulnerable < $max_safe)\e[0m"
                            
                            # Check for known CVEs
                            cve_key="$lib<$max_safe"
                            if [[ -n "${CVE_DB[$cve_key]}" ]]; then
                                echo -e "\e[1;31m[!] Known CVEs: ${CVE_DB[$cve_key]}\e[0m"
                            fi
                            
                            # Add exploitation suggestion if --exploit flag is set
                            if [[ "$2" == "--exploit" ]]; then
                                case "$lib" in
                                    "jQuery")
                                        echo -e "\e[1;33m[!] Exploit Suggestion: Try XSS payloads with jQuery.html()\e[0m"
                                        ;;
                                    "Lodash")
                                        echo -e "\e[1;33m[!] Exploit Suggestion: Check for prototype pollution vulnerabilities\e[0m"
                                        ;;
                                    *)
                                        echo -e "\e[1;33m[!] Check exploit-db.com for known exploits\e[0m"
                                        ;;
                                esac
                            fi
                        else
                            echo -e "\e[1;32m[✓] Version $version appears safe\e[0m"
                        fi
                    fi
                fi
            fi
        done
    done < "$OUTPUT_DIR/js_files.txt"
}

# Main execution
fetch_js_files
check_libraries "$@"

# Final output
echo -e "\e[1;36m\n[+] Scan complete! Detailed results saved to $OUTPUT_DIR/\e[0m"
echo -e "\e[1;35m[!] Remember to verify findings manually before reporting\e[0m"
