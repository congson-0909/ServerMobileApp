module.exports = function (_, url) {
  const highRiskKeywords = [
    "malware", "phishing", "free-download", "crack", "keygen", "serial",
    "patch", "installer", "driver-update"
  ];

  const riskKeywords = [
    "login", "free", "verify", "update", "account", "win", "gift", "confirm",
    "bank", "secure", "password", "reset", "claim", "access", "prize",
    "security", "signin", "support", "payment", "unlock", "banking",
    "paypal", "refund", "reset-password"
  ];

  const lowerUrl = url.toLowerCase();
  const foundHighRisk = highRiskKeywords.filter(k => lowerUrl.includes(k));
  const foundRisk = riskKeywords.filter(k => lowerUrl.includes(k));

  const totalScore = (foundRisk.length * 1) + (foundHighRisk.length * 3);

  if (totalScore > 0) {
    const reasons = [];
    if (foundRisk.length > 0)
      reasons.push(`Contain suspicious keywords: ${foundRisk.join(", ")}`);
    if (foundHighRisk.length > 0)
      reasons.push(`Contain High-risk keywords: ${foundHighRisk.join(", ")}`);

    return {
      score: totalScore,
      reason: reasons.join(" | ")
    };
  }
};