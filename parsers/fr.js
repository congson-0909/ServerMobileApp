const whoisRaw = require('whois');

module.exports = async (domain, whoisData) => {
  const rawText = await new Promise((resolve, reject) => {
    whoisRaw.lookup(domain, {
      server: 'whois.nic.fr',
      follow: 0,
      timeout: 7000
    }, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });

  const extract = (label) => {
    const re = new RegExp(`^${label}:\\s*(.+)$`, 'im');
    const m = rawText.match(re);
    return m ? m[1].trim() : null;
  };

  const parseDate = (text) => {
    if (!text) return null;
    const match = text.match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (match) {
      const [, y, m, d] = match;
      return `${y}-${m}-${d}`;
    }
    return null;
  };

  const nameServers = [];
  const nsMatches = rawText.match(/^nserver:\s+([^\s]+)/gim);
  if (nsMatches) {
    nameServers.push(...nsMatches.map(line => line.replace(/^nserver:\s+/i, '').trim()));
  }

  const info = {
    domain: extract('domain') || domain,
    registrar: extract('registrar') || whoisData.registrar || null,
    registrant: extract('holder-c') || extract('org') || null,
    registeredOn: parseDate(extract('created')),
    lastUpdated: parseDate(extract('last-update')),
    expiresOn: parseDate(extract('Expiry Date')), // Có thể không tồn tại
    nameServers,
    country: 'FR'
  };

  return info;
};