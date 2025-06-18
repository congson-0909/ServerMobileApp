const analyzeStructure = require("./analyzeStructure");
const analyzeWhois = require("./analyzeWhois");
const analyzeIpInfo = require("./analyzeIpInfo");
const checkUrlhaus = require("./checkUrlhaus");
const checkGSB = require("./checkGSB");
const analyzeBehavior = require("./analyzeSandbox");
const axios = require("axios"); // ✅ NEW
const { URL } = require("url");

function isSpecialDomain(hostname) {
  const specialPatterns = [
    "example.com", "example.net", "example.org",
    "localhost", "127.0.0.1", "::1", "dev.local", "staging.local", "localtest.me",
    "test", "invalid", "local", "onion"
  ];
  return specialPatterns.some(pattern =>
    hostname === pattern || hostname.endsWith(`.${pattern}`)
  );
}

function isIpAddress(hostname) {
  return /^[\d.]+$/.test(hostname);
}

// ✅ NEW: Hàm gọi ML model qua ngrok
async function getMLPrediction(url) {
  try {
    const response = await axios.post(
      "https://ff78-112-197-86-109.ngrok-free.app/predict",
      { url },
      { headers: { "Content-Type": "application/json" } }
    );
    return response.data;
  } catch (error) {
    console.error("ML prediction error:", error.message);
    return {
      prediction: "unknown",
      probability: {},
      score: 0
    };
  }
}

async function analyze(url) {
  const structureResult = analyzeStructure(url);

  let whoisResult = {
    score: 0,
    risk: "unknown",
    reasons: ["WHOIS skipped for special or non-public domain"]
  };

  let urlhausResult = { found: false, score: 0, reasons: [] };
  let gsbResult = { found: false, score: 0, threatTypes: [], reasons: [] };

  let behaviorResult = {
    score: 0,
    suspicious: false,
    reasons: ["Behavior analysis skipped"],
    details: {}
  };

  let mlResult = {
    prediction: "unknown",
    probability: {},
    score: 0
  };

  try {
    const parsed = new URL(url.startsWith("http") ? url : `http://${url}`);
    const hostname = parsed.hostname;

    if (!isSpecialDomain(hostname)) {
      if (isIpAddress(hostname)) {
        whoisResult = await analyzeIpInfo(hostname);
      } else {
        whoisResult = await analyzeWhois(url);
      }

      gsbResult = await checkGSB(url);
      if (!gsbResult.found) {
        urlhausResult = await checkUrlhaus(url);
      }

      behaviorResult = await analyzeBehavior(url);

      mlResult = await getMLPrediction(url); // ✅ NEW: ML
    }
  } catch (err) {
    whoisResult = {
      score: 0,
      risk: "unknown",
      reasons: ["Invalid hostname format or URL"]
    };
  }

  const gsbOrUrlhausScore = gsbResult.found
    ? gsbResult.score
    : urlhausResult.found
    ? urlhausResult.score
    : 0;

  // 🔁 EDIT: tính finalScore có cả ML
  const score =
    structureResult.score +
    whoisResult.score +
    gsbOrUrlhausScore +
    behaviorResult.score +
    mlResult.score;

  // 🔁 EDIT: xét finalRisk có thêm ML score
  let finalRisk = "safe";
  if (gsbResult.found || urlhausResult.found) {
    finalRisk = "dangerous";
  } else if (score >= 10) {
    finalRisk = "dangerous";
  } else if (score >= 5) {
    finalRisk = "suspicious";
  }

  const APIdetect = {};
  if (gsbResult.found) {
    APIdetect.gsb = gsbResult;
  } else if (urlhausResult.found) {
    APIdetect.urlhaus = urlhausResult;
  } else {
    APIdetect.score = 0;
    APIdetect.reasons = ["Not detected by Google Safe Browsing or URLhaus"];
  }

  // ✅ FINAL OUTPUT
  return {
    url,
    finalScore: score,
    finalRisk,
    structure: structureResult,
    whois: whoisResult,
    APIdetect,
    ml: mlResult,
    behavior: behaviorResult
     // ✅ NEW: ML Result xuất hiện trong JSON trả về
  };
}

module.exports = analyze;
