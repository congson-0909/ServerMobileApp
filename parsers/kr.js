const whoisRaw = require('whois');

module.exports = async (domain, whoisData) => {
  const rawText = await new Promise((resolve, reject) => {
    whoisRaw.lookup(domain, { server: 'whois.kr', follow: 0, timeout: 5000 }, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });

  const extract = (label) => {
    const re = new RegExp(`${label}\\s*:\\s*(.+)`, 'i');
    const match = re.exec(rawText);
    return match ? match[1].trim() : null;
  };

  return {
    domain: extract('Domain Name') || domain,
    registrant: extract('Registrant'),
    registeredOn: extract('Registered Date')?.replace(/\./g, '-').slice(0, -1),
    lastUpdated: extract('Last Updated Date')?.replace(/\./g, '-').slice(0, -1),
    expiresOn: extract('Expiration Date')?.replace(/\./g, '-').slice(0, -1),
    nameServers: rawText.match(/Name Server\s*:\s*(.+)/gi)?.map(ns => ns.split(':')[1].trim()) || [],
    country: 'KR'
  };
};