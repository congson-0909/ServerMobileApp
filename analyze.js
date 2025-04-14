const analyzeStructure = require("./analyzeStructure");
const analyzeWhois = require("./analyzeWhois");
const { URL } = require("url");

function isSpecialDomain(hostname) {
  const specialPatterns = [
    "example.com", "example.net", "example.org",
    "localhost", "test", "invalid", "local", "onion"
  ];
  return specialPatterns.some(pattern => hostname.endsWith(pattern) || hostname === pattern);
}

async function analyze(url) {
  const structureResult = analyzeStructure(url);

  let whoisResult = {
    score: 0,
    risk: "unknown",
    reasons: ["WHOIS skipped for special or non-public domain"],
  };

  try {
    const parsed = new URL(url.startsWith("http") ? url : `http://${url}`);
    const hostname = parsed.hostname;

    if (!isSpecialDomain(hostname)) {
      whoisResult = await analyzeWhois(url);
    }
  } catch (err) {
    whoisResult = {
      score: 0,
      risk: "unknown",
      reasons: ["Invalid hostname format or URL"],
    };
  }

  const score = structureResult.score + whoisResult.score;

  let finalRisk = "safe";
  if (score >= 6) finalRisk = "dangerous";
  else if (score >= 3) finalRisk = "suspicious";
  if (whoisResult.risk === "unknown") finalRisk = "unknown";

  return {
    url,
    finalScore: score,
    finalRisk,
    structure: structureResult,
    whois: whoisResult,
  };
}

module.exports = analyze;