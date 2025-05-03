module.exports = function(parsed) {
    const parts = parsed.hostname.split(".");
    if (parts.length > 4) {
      return { score: 1, reason: "Too many subdomains" };
    }
  };