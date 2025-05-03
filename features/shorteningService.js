const shorteners = [
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "adf.ly", "t.co"
  ];
  
  module.exports = function(parsed) {
    if (shorteners.includes(parsed.hostname)) {
      return { score: 1, reason: "Uses URL shortening service" };
    }
  };