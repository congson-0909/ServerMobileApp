
module.exports = function (_, url) {
    const cheapTLDs = [
      "xyz", "top", "tk", "gq", "ml", "cf", "pw", "click", "info", "online"
    ];
  
    const abusedTLDs = [
      "zip", "review", "support", "live", "lol", "buzz", "party", "fit"
    ];
  
    const lowCensorshipTLDs = [
      "cn", "ru", "su", "ir"
    ];
  
    const parsed = new URL(url.startsWith("http") ? url : `http://${url}`);
    const hostname = parsed.hostname;
    const parts = hostname.split(".");
    const tld = parts[parts.length - 1].toLowerCase();
  
    let score = 0;
    let reasons = [];
  
    if (cheapTLDs.includes(tld)) {
      score += 2;
      reasons.push(`Uses cheap or easily registered TLD .`);
    }
  
    if (abusedTLDs.includes(tld)) {
      score += 3;
      reasons.push(`Uses suspicious or commonly abused TLD.`);
    }
  
    if (lowCensorshipTLDs.includes(tld)) {
      score += 3;
      reasons.push(`Uses TLD from low-censorship country.`);
    }
  
    if (score > 0) {
      return {
        score,
        reason: reasons.join(" | ")
      };
    }
  };