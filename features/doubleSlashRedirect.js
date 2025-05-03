module.exports = function(_, url) {
    const path = url.split("//").slice(2).join("//");
    if (path.includes("//")) {
      return { score: 1, reason: "Contains double slash redirection" };
    }
  };