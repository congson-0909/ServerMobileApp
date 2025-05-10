const whoisRaw = require('whois');

module.exports = async (domain, whoisData) => {
  const rawText = await new Promise((resolve, reject) => {
    whoisRaw.lookup(domain, { server: 'whois.cnnic.cn', follow: 0, timeout: 5000 }, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });

  const extract = (label) => {
    const re = new RegExp(`${label}:\\s*(.+)`, 'i');
    const match = re.exec(rawText);
    return match ? match[1].trim() : null;
  };

  return {
    domain: extract('Domain Name') || domain,
    registrar: extract('Sponsoring Registrar'),
    registrant: extract('Registrant'),
    registeredOn: extract('Registration Time'),
    lastUpdated: extract('Last Updated Time'),
    expiresOn: extract('Expiration Time'),
    nameServers: rawText.match(/Name Server:\s*(.+)/gi)?.map(ns => ns.split(':')[1].trim()) || [],
    country: 'CN'
  };
};