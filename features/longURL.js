module.exports = function(_, url) {
    if (url.length > 100) {
      return { score: 1, reason: "URL is too long" };
    }
  };