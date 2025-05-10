const whoisRaw = require('whois');

module.exports = async (domain, whoisData) => {
  const rawText = await new Promise((resolve, reject) => {
    whoisRaw.lookup(domain, { server: 'whois.registry.in', follow: 0, timeout: 7000 }, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });

  const extract = (label) => {
    const re = new RegExp(`^${label}:\\s*(.+)$`, 'im');
    const m = rawText.match(re);
    return m ? m[1].trim() : null;
  };

  return {
    domain: extract('Domain Name') || domain,
    registrar: extract('Registrar'),
    registrant: extract('Registrant Organization') || extract('Registrant Name'),
    registeredOn: extract('Creation Date'),
    lastUpdated: extract('Updated Date'),
    expiresOn: extract('Expiry Date'),
    nameServers: (rawText.match(/^Name Server:\s*(.+)$/gim) || []).map(line => line.replace(/^Name Server:\s*/i, '').trim()),
    country: 'IN'
  };
};