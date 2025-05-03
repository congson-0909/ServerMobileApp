module.exports = function(_, url) {
    if (url.includes("@")) {
      return { score: 1, reason: "URL contains '@' symbol" };
    }
  };