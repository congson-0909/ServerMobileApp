const fs = require("fs");
const path = require("path");

const featuresDir = path.join(__dirname, "features");
const featureFiles = fs.readdirSync(featuresDir);
const featureFunctions = featureFiles.map(file => require(`./features/${file}`));

function analyzeURL(url) {
  let score = 0;
  const reasons = [];

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { score: 0, risk: "unknown", reasons: ["Invalid URL"] };
  }

  for (const check of featureFunctions) {
    const result = check(parsed, url);
    if (result) {
      score += result.score;
      reasons.push(result.reason);
    }
  }

  const risk = score >= 6 ? "dangerous" : score >= 3 ? "suspicious" : "safe";
  return { score, risk, reasons };
}

module.exports = analyzeURL;