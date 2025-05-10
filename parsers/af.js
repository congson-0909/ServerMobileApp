const whoisRaw = require('whois');

module.exports = async (domain, whoisData) => {
  const rawText = await new Promise((resolve, reject) => {
    whoisRaw.lookup(domain, { server: 'whois.nic.af', follow: 0, timeout: 7000 }, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });

  const extract = (label) => {
    const re = new RegExp(`^\\s*${label}:\\s*(.+)$`, 'gim');
    const m = re.exec(rawText);
    return m ? m[1].trim() : null;
  };

  const nameServers = rawText
    .split(/\r?\n/)
    .filter(line => /^Name Server:/i.test(line))
    .map(line => line.replace(/^Name Server:\s*/i, '').trim());

  const info = {
    domain: extract('Domain Name') || domain,
    registrar: extract('Sponsoring Registrar') || whoisData.registrar || null,
    registrant: extract('Registrant Name') || null,
    registeredOn: extract('Creation Date'),
    lastUpdated: extract('Updated Date'),
    expiresOn: extract('Registry Expiry Date'),
    nameServers,
    country: 'AF',
  };

  return info;
};
