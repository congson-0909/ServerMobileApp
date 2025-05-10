const whoisRaw = require('whois');

module.exports = async (domain, whoisData) => {
  const rawText = await new Promise((resolve, reject) => {
    whoisRaw.lookup(domain, { server: 'whois.denic.de', follow: 0, timeout: 5000 }, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });

  const extract = (label) => {
    const re = new RegExp(`^\\s*${label}:\\s*(.+)$`, 'gim');
    const m = re.exec(rawText);
    return m ? m[1].trim() : null;
  };

  const info = {
    domain: extract('Domain') || domain,
    registrar: extract('Registrar') || whoisData.registrar || null,
    registrant: extract('Holder') || null,
    registeredOn: extract('Created'),
    lastUpdated: null,
    expiresOn: null, // DENIC không cung cấp ngày hết hạn
    nameServers: rawText
      .split(/\r?\n/)
      .filter(line => /^Name server:/i.test(line))
      .map(line => line.replace(/^Name server:\s*/i, '').trim())
      .filter(Boolean),
    country: 'DE'
  };

  return info;
};
