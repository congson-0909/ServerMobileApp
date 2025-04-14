const whois = require("whois-json");
const { parse } = require("tldts");
const fs = require("fs");
const path = require("path");
const whoisRaw = require('whois');
function getTLD(domain) {
  const parts = domain.toLowerCase().split(".");
  const tldCandidates = [];
  for (let i = 1; i < parts.length; i++) {
    const tld = parts.slice(parts.length - i).join(".");
    tldCandidates.push(tld);
  }
  const parserFiles = fs.readdirSync(path.join(__dirname, "parsers"));
  const availableParsers = parserFiles.map(f => f.replace(".js", ""));
  for (const tld of tldCandidates) {
    if (availableParsers.includes(tld)) return tld;
  }
  return "default";
}

function getParser(tld) {
  try {
    return require(`./parsers/${tld}.js`);
  } catch {
    return require("./parsers/default.js");
  }
}
function parseRelevantDate(dateStr) {
  if (!dateStr) return null;

  const lower = dateStr.toLowerCase();
  const match = lower.match(/(?:before\s*)?([a-z]{3,9})?-?(\d{4})/i);

  if (match) {
    const monthStr = match[1] || "Jan"; 
    const year = parseInt(match[2], 10);
    const months = {
      jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6,
      jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12
    };
    const month = months[monthStr.toLowerCase()] || 1;
    return new Date(`${year}-${String(month).padStart(2, "0")}-01`);
  }

  return null;
}

async function analyzeWhois(url) {
  try {
    let domain;
    try {
      const parsed = new URL(url.startsWith("http") ? url : `http://${url}`);
      domain = parse(parsed.hostname).domain;
    } catch {
      domain = parse(url).domain || url;
    }

    const tld = getTLD(domain);
    const parser = getParser(tld);
    const whoisData = await whois(domain);
    const raw = parser(domain, whoisData);


    let creationDateRaw =
      whoisData.creationDate ||
      whoisData.createdDate ||
      whoisData["Creation Date"];

    let creationDate;
    if (!creationDateRaw && whoisData.relevantDates) {
      creationDate = parseRelevantDate(whoisData.relevantDates);
    } else {
      creationDate = new Date(creationDateRaw);
    }

    if (!creationDate || isNaN(creationDate)) {
      creationDate = new Date("1970-01-01");
    }

    const now = new Date();
    const ageInDays = Math.floor((now - creationDate) / (1000 * 60 * 60 * 24));
    const isRecentlyRegistered = ageInDays < 180;

    const registrant =
      whoisData.registrantOrganization ||
      whoisData.registrantName ||
      whoisData.org ||
      "";

    const isHidden =
      registrant.toLowerCase().includes("redacted") ||
      registrant.toLowerCase().includes("privacy");

    let score = 0;
    const reasons = [];
    if (isRecentlyRegistered) {
      score += 1;
      reasons.push("Domain recently registered");
    }
    if (isHidden) {
      score += 1;
      reasons.push("Registrant info is hidden");
    }

    const country =
      raw.country ||
      whoisData.registrantCountry ||
      whoisData.adminCountry ||
      null;

    return {
      domain,
      country,
      creationDate: creationDate.toISOString(),
      isRecentlyRegistered,
      isRegistrantHidden: isHidden,
      score,
      risk: score >= 2 ? "suspicious" : "safe",
      reasons
    };
  } catch (err) {
    return { error: "WHOIS lookup failed", score: 0, risk: "unknown", reasons: [] };
  }
}

module.exports = analyzeWhois;