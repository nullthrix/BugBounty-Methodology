const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

function appendUnique(file, items) {
  const filePath = path.resolve(file);
  let existing = new Set();

  if (fs.existsSync(filePath)) {
    const content = fs.readFileSync(filePath, 'utf-8');
    existing = new Set(content.split(/\r?\n/).filter(Boolean));
  }

  const newItems = items.filter(i => !existing.has(i));
  if (newItems.length > 0) {
    fs.appendFileSync(filePath, newItems.join('\n') + '\n');
  }
}

async function scanDomain(url) {
  const domain = new URL(url).hostname;
  console.log(`Running ${domain}`);

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.goto(url, { waitUntil: 'networkidle2' });

  const { endpoints, params, jsFiles } = await page.evaluate(async (targetDomain) => {
    const regex = /(?<=(["'`]))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(["'`]))/g;
    const jsRegex = /(?<=(["'`]))(?:\/|https?:\/\/)[a-zA-Z0-9_?&=\/\-\#\.]+\.js(?:\?[^"'`]*)?(?=(["'`]))/g;

    const results = new Set();
    const paramSet = new Set();
    const jsFiles = new Set();

    function sameDomain(url) {
      try {
        const u = new URL(url, window.location.origin);
        return u.hostname === targetDomain || u.hostname.endsWith("." + targetDomain);
      } catch {
        return false;
      }
    }

    function processContent(content) {
      const matches = content.matchAll(regex);
      for (let m of matches) {
        results.add(m[0]);
        const query = m[0].split('?')[1];
        if (query) {
          query.split('&').forEach(param => {
            const [key] = param.split('=');
            if (key) paramSet.add(key);
          });
        }
      }
      const jsMatches = content.matchAll(jsRegex);
      for (let m of jsMatches) {
        if (sameDomain(m[0])) jsFiles.add(m[0]);
      }
    }

    const scripts = Array.from(document.getElementsByTagName("script"));
    for (let s of scripts) {
      if (s.src) {
        if (sameDomain(s.src)) jsFiles.add(s.src);
        try {
          const resp = await fetch(s.src);
          const text = await resp.text();
          processContent(text);
        } catch (e) {}
      } else {
        processContent(s.innerText);
      }
    }

    processContent(document.documentElement.outerHTML);

    return {
      endpoints: Array.from(results),
      params: Array.from(paramSet),
      jsFiles: Array.from(jsFiles)
    };
  }, domain);

  appendUnique("endpoints.txt", endpoints);
  appendUnique("parameters.txt", params);
  appendUnique("jsfiles.txt", jsFiles);

  await browser.close();
}

(async () => {
  const input = process.argv[2];
  if (!input) {
    console.error("Usage: node dom-scan.js <URL or file>");
    process.exit(1);
  }

  if (fs.existsSync(input)) {
    // Treat as file containing multiple domains/subdomains
    const urls = fs.readFileSync(input, 'utf-8').split(/\r?\n/).filter(Boolean);
    for (const url of urls) {
      try {
        await scanDomain(url);
      } catch (err) {
        console.error(`Error scanning ${url}: ${err.message}`);
      }
    }
  } else {
    // Single URL
    await scanDomain(input);
  }
  process.exit(0);   // <---- add this
})();
