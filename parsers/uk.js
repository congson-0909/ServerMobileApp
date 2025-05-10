const whoisRaw = require('whois');
module.exports = async (domain , whoisData) => {
  const rawText = await new Promise((resolve, reject) => {
    whoisRaw.lookup(domain, { server: 'whois.nic.uk', follow: 0, timeout: 5000 }, (err, data) => {
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
    domain: extract('Domain name') || domain,
    registrar: extract('Registrar') || whoisData.registrar || null,
    registrant: extract('Registrant') || extract('Registrant company') || null,
    registeredOn: extract('Registered on'),
    lastUpdated: extract('Last updated'),
    expiresOn: extract('Expiry date'),
    nameServers: rawText
      .split(/\r?\n/)
      .filter(line => /^\s*Name servers?:/i.test(line) || /^\s+[a-z0-9.-]+\.[a-z]{2,}/i.test(line))
      .map(l => l.replace(/^(Name servers?:)?\s*/i, '').trim())
      .filter(Boolean),
    country: 'UK'
  };

  return info;
};