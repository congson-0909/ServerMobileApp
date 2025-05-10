const keywords = [
    "login", "free", "verify", "update", "account", "win", "gift", "confirm",
    "bank", "secure", "password", "reset", "claim", "access", "prize",
    "security", "signin", "support", "payment", "unlock" ,"malware" ,"phishing"
  ];
  
  module.exports = function(_, url) {
    const found = keywords.filter(k => url.toLowerCase().includes(k));
    if (found.length > 0) {
      return { score: found.length, reason: `Contains suspicious keywords: ${found.join(", ")}` };
    }
  };