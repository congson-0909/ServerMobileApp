const whoisRaw = require('whois');

module.exports = async (domain, whoisData) => {
  const rawText = await new Promise((resolve, reject) => {
    whoisRaw.lookup(domain, { server: 'whois.tcinet.ru', follow: 0, timeout: 7000 }, (err, data) => {
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
    domain: extract('domain') || domain,
    registrar: extract('registrar'),
    registrant: extract('org'),
    registeredOn: extract('created'),
    lastUpdated: extract('Last updated'),
    expiresOn: extract('paid-till'),
    nameServers: (rawText.match(/^nserver:\s*(.+)$/gim) || []).map(line => line.replace(/^nserver:\s*/i, '').trim()),
    country: 'RU'
  };
};
