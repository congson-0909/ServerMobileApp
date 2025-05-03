module.exports = function(parsed) {
    const ipRegex = /^\d{1,3}(\.\d{1,3}){3}$/;
    if (ipRegex.test(parsed.hostname)) {
      return { score: 2, reason: "Uses IP address" };
    }
  };