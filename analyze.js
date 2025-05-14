const analyzeStructure = require("./analyzeStructure");
const analyzeWhois = require("./analyzeWhois");
const checkUrlhaus = require("./checkUrlhaus");
const checkGSB = require("./checkGSB"); // 🆕
const { URL } = require("url");

function isSpecialDomain(hostname) {
  const specialPatterns = [
    "example.com", "example.net", "example.org",
    "localhost", "127.0.0.1", "::1", "dev.local", "staging.local", "localtest.me",
    "test", "invalid", "local",
    "onion"
  ];
  return specialPatterns.some(pattern =>
    hostname === pattern || hostname.endsWith(`.${pattern}`)
  );
}

async function analyze(url) {
  const structureResult = analyzeStructure(url);

  let whoisResult = {
    score: 0,
    risk: "unknown",
    reasons: ["WHOIS skipped for special or non-public domain"]
  };

  let urlhausResult = { detected: false };

  let gsbResult = { found: false, threatTypes: [], score: 0 };

  try {
    const parsed = new URL(url.startsWith("http") ? url : `http://${url}`);
    const hostname = parsed.hostname;

    if (!isSpecialDomain(hostname)) {
      whoisResult = await analyzeWhois(url);
      urlhausResult = await checkUrlhaus(url);
      gsbResult = await checkGSB(url);
      urlhausResult = await checkUrlhaus(url);
    }
  } catch (err) {
    whoisResult = {
      score: 0,
      risk: "unknown",
      reasons: ["Invalid hostname format or URL"]
    };
  }

  const score = structureResult.score + whoisResult.score + urlhausResult.score + gsbResult.score;

  let finalRisk = "safe";
  if (score >= 8) finalRisk = "dangerous";
  else if (score >= 4) finalRisk = "suspicious";
  if (gsbResult.found || urlhausResult.detected) finalRisk = "dangerous";

  return {
    url,
    finalScore: score,
    finalRisk,
    structure: structureResult,
    whois: whoisResult,
    urlhaus: urlhausResult,
    gsb: gsbResult 
  };
}

module.exports = analyze;
