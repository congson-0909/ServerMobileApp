module.exports = function (_, url) {
    const suspiciousExtensions = [
      ".exe", ".scr", ".zip", ".bat", ".js", ".vbs", ".apk", ".dll", ".msi"
    ];
  
    const suspiciousParams = [
      ".php?download", ".asp?run"
    ];
  
    const suspiciousKeywords = [
      "installer", "setup", "crack", "update", "patch"
    ];
  
    const lowerUrl = url.toLowerCase();
    let score = 0;
    let reasons = [];
  
    // Kiểm tra phần mở rộng
    suspiciousExtensions.forEach(ext => {
      if (lowerUrl.includes(ext)) {
        score += 2;
        reasons.push(`Contains suspicious file extension.`);
      }
    });
  
    // Kiểm tra các tham số đáng ngờ
    suspiciousParams.forEach(p => {
      if (lowerUrl.includes(p)) {
        score += 2;
        reasons.push(`Contains suspicious download/run pattern.`);
      }
    });
  
    // Kiểm tra các keyword trong endpoint
    suspiciousKeywords.forEach(keyword => {
      if (lowerUrl.includes(keyword)) {
        score += 1;
        reasons.push(`Contains suspicious keyword.`);
      }
    });
  
    if (score > 0) {
      return {
        score,
        reason: reasons.join(" | ")
      };
    }
  };