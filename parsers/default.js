module.exports = (domain, whoisData) => {
  function getExpireDateFromWhois(data) {
    for (const key in data) {
      if (key.toLowerCase().includes("expir") && data[key]) {
        return data[key];
      }
    }
    return null;
  }
  const result = {
    domain,
    registrar: whoisData.registrar || null,
    country: whoisData.registrantCountry || whoisData.adminCountry || whoisData.techCountry || null,
    creationDate: whoisData.creationDate || whoisData.createdDate || null,
    updatedDate: whoisData.updatedDate || null,
    expiresDate: getExpireDateFromWhois(whoisData),

  };
  return result;
};