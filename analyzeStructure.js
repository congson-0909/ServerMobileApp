const { URL } = require("url");

const suspiciousKeywords = [
  "login", "free", "verify", "update", "account", "win", "gift", "confirm",
  "bank", "secure", "password", "reset", "claim", "access", "prize",
  "security", "signin", "support", "payment", "unlock"
];

function isIPAddress(hostname) {
  const ipRegex = /^\d{1,3}(\.\d{1,3}){3}$/;
  return ipRegex.test(hostname);
}

function analyzeStructure(url) {
  let score = 0;
  const result = { reasons: [] };
  try {
    const parsed = new URL(url);

    // HTTP protocol instead of HTTPS
    if (parsed.protocol === "http:") {
      score += 1;
      result.reasons.push("Uses insecure HTTP protocol");
    }

    // Uses IP address instead of domain
    if (isIPAddress(parsed.hostname)) {
      score += 2;
      result.reasons.push("Uses IP address");
    }

    // URL length too long
    if (url.length > 100) {
      score += 1;
      result.reasons.push("URL is too long");
    }

    // Special characters
    if (url.match(/[%@!$]/)) {
      score += 1;
      result.reasons.push("Contains special characters");
    }

    // Suspicious keywords
    suspiciousKeywords.forEach((keyword) => {
      if (url.toLowerCase().includes(keyword)) {
        score += 1;
        result.reasons.push(`Contains suspicious keyword: ${keyword}`);
      }
    });

    // Too many hyphens in domain
    const dashCount = (parsed.hostname.match(/-/g) || []).length;
    if (dashCount >= 3) {
      score += 1;
      result.reasons.push("Suspicious use of hyphens in domain");
    }

    // Too many subdomains
    const subdomainParts = parsed.hostname.split(".");
    if (subdomainParts.length > 4) {
      score += 1;
      result.reasons.push("Too many subdomains");
    }

    // Uncommon port usage
    if (parsed.port && parsed.port !== "80" && parsed.port !== "443") {
      score += 1;
      result.reasons.push(`Uses uncommon port: ${parsed.port}`);
    }

    // Long path
    if (parsed.pathname.length > 50) {
      score += 1;
      result.reasons.push("Long path in URL");
    }

    // Long query string
    if (parsed.search && parsed.search.length > 50) {
      score += 1;
      result.reasons.push("Long query string");
    }

    // Unicode / suspicious characters (IDN homograph)
    if (/[\u0100-\uffff]/.test(parsed.hostname)) {
      score += 1;
      result.reasons.push("Domain contains suspicious Unicode characters");
    }

    // Invalid TLD (domain lacks a .com/.net/etc.)
    if (!parsed.hostname.includes(".")) {
      score += 1;
      result.reasons.push("Domain lacks a valid TLD");
    }

    let risk = "safe";
    if (score >= 6) risk = "dangerous";
    else if (score >= 3) risk = "suspicious";

    return { score, risk, reasons: result.reasons };
  } catch {
    return { score: 0, risk: "unknown", reasons: ["Invalid URL"] };
  }
}

module.exports = analyzeStructure;