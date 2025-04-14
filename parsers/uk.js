module.exports = (domain, whoisData) => {
  let creationDate = null;

  // Kiểm tra nếu có trường 'relevantDates' và trích xuất ngày đăng ký
  if (whoisData.relevantDates) {
    const match = whoisData.relevantDates.match(/Registered on:\s*(.+)/i);
    if (match) {
      creationDate = match[1].trim();
    }
  }

  // Nếu không tìm thấy trong 'relevantDates', kiểm tra các trường khác
  if (!creationDate) {
    creationDate =
      whoisData.creationDate ||
      whoisData.createdDate ||
      whoisData["Creation Date"] ||
      null;
  }

  const info = {
    domain,
    registrar: whoisData.registrar || null,
    country: "UK",
    creationDate,
    updatedDate: whoisData.lastUpdated || null,
    expiresDate: whoisData.expiryDate || null,
    
    
  };

  return info;
}; 