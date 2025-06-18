const analyzeStructure = require("./analyzeStructure");
const analyzeWhois = require("./analyzeWhois");
const analyzeIpInfo = require("./analyzeIpInfo");
const checkUrlhaus = require("./checkUrlhaus");
const checkGSB = require("./checkGSB");
const analyzeBehavior = require("./analyzeSandbox");
const axios = require("axios");
const { URL } = require("url");

const ML_API_URL = "https://c415-112-197-86-109.ngrok-free.app/predict";

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
async function getMLPrediction(url) {
  try {
    const response = await axios.post(
      ML_API_URL,
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

// ✅ Clean sandbox result nếu không có lý do rõ ràng
function cleanSandboxResult(result) {
  if (
    !result.reasons ||
    result.reasons.length === 0 ||
    (result.reasons.length === 1 &&
     result.reasons[0].includes("ERR_BLOCKED_BY_CLIENT"))
  ) {
    return {
      ...result,
      reasons: ["Not detected by Sandbox Testing"]
    };
  }
  return result;
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

      behaviorResult = cleanSandboxResult(await analyzeBehavior(url));
      mlResult = await getMLPrediction(url);
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

  // ✅ Tổng điểm tổng hợp
  const score =
    structureResult.score +
    whoisResult.score +
    gsbOrUrlhausScore +
    behaviorResult.score +
    mlResult.score;

  // ✅ Đánh giá rủi ro cuối cùng
  let finalRisk = "safe";
  if (gsbResult.found || urlhausResult.found) {
    finalRisk = "dangerous";
  } else if (score >= 10) {
    finalRisk = "dangerous";
  } else if (score >= 5) {
    finalRisk = "suspicious";
  }

  // ✅ Kết quả API detect
  const APIdetect = {};
  if (gsbResult.found) {
    APIdetect.gsb = gsbResult;
  } else if (urlhausResult.found) {
    APIdetect.urlhaus = urlhausResult;
  } else {
    APIdetect.score = 0;
    APIdetect.reasons = ["Not detected by Google Safe Browsing or URLhaus"];
  }

  // ✅ Trả kết quả cuối cùng
  return {
    url,
    finalScore: score,
    finalRisk,
    structure: structureResult,
    whois: whoisResult,
    APIdetect,
    ml: mlResult,
    behavior: behaviorResult
  };
}

module.exports = analyze;
