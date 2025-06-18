// analyzeBehavior.js
const puppeteer = require('puppeteer');

async function analyzeBehavior(url) {
  if (!url || !url.startsWith('http')) {
    return {
      score: 0,
      suspicious: false,
      reasons: ['Invalid or unsupported URL format'],
      details: {}
    };
  }

  try {
    const browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();
    let requests = [];

    page.on('request', request => {
      requests.push(request.url());
    });

    await page.goto(url, { timeout:4000, waitUntil: 'networkidle2' });

    const suspiciousRequests = requests.filter(r =>
      r.includes('.exe') || r.includes('.apk') || r.includes('dropbox') || r.includes('mediafire')
    );

    const iframeCount = await page.$$eval('iframe', els => els.length);
    const scriptCount = await page.$$eval('script', els => els.length);
    const formCount = await page.$$eval('form', els => els.length);

    await browser.close();

    let score = 0;
    let reasons = [];

    if (suspiciousRequests.length > 0) {
      score += 2;
      reasons.push('Suspicious file download request detected');
    }
    if (requests.length > 3) {
      score += 1;
      reasons.push('High number of network requests');
    }
    if (iframeCount > 0) {
      score += 1;
      reasons.push('Page contains iframe(s)');
    }
    if (scriptCount > 0) {
      score += 1;
      reasons.push('Page contains script(s)');
    }
    if (formCount > 0) {
      score += 1;
      reasons.push('Page contains form(s)');
    }

    return {
      score,
      suspicious: score >= 3,
      reasons,
      details: {
        totalRequests: requests.length,
        suspiciousRequests,
        iframeCount,
        scriptCount,
        formCount
      }
    };
  } catch (err) {
    return {
      score: 0,
      reasons: [],
    };
  }
}

module.exports = analyzeBehavior;
