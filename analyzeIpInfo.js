// analyzeIpInfo.js
const axios = require('axios');

const riskyCountries = ['CN', 'RU', 'IR', 'SU'];
const cloudProviders = ['digitalocean', 'ovh', 'contabo', 'linode', 'vultr', 'amazon', 'aws', 'google', 'gcp', 'microsoft', 'azure'];

async function analyzeIp(ip) {
  const { data } = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,countryCode,as,isp,org`);

  if (data.status !== 'success') {
    throw new Error(data.message || 'Failed to get IP info');
  }

  const result = {
    ip,
    countryCode: data.countryCode,
    asn: data.as,
    isp: data.isp,
    org: data.org,
    score: 0,
    reasons: []
  };

  // Rule 1: Risky country
  if (riskyCountries.includes(data.countryCode)) {
    result.score += 3;
    result.reasons.push(`IP from high-risk country: ${data.countryCode}`);
  }

  // Rule 2: ASN unknown or generic
  if (!data.as || data.as.toLowerCase().includes('unknown')) {
    result.score += 2;
    result.reasons.push('ASN is unknown or suspicious');
  }

  // Rule 3: Netname/Org missing or vague
  if (!data.org || data.org.length < 3) {
    result.score += 1;
    result.reasons.push('Org/Netname is missing or too short');
  }

  // Rule 4: ISP/Org is cloud provider
  const lowerIsp = `${data.isp} ${data.org}`.toLowerCase();
  if (cloudProviders.some(p => lowerIsp.includes(p))) {
    result.score += 2;
    result.reasons.push('IP belongs to a common cloud provider');
  }

  return result;
}

module.exports = analyzeIp;
