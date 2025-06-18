const axios = require("axios");

const GSB_API_KEY = "AIzaSyBd_EX5XKA-5PqIUF0do3qW3K-ktL8PJJc";

function scoreThreatTypes(threatTypes) {
  const scoreMap = {
    MALWARE: 10,
    SOCIAL_ENGINEERING: 10,
    UNWANTED_SOFTWARE: 5,
    POTENTIALLY_HARMFUL_APPLICATION: 5
  };

  const reasonsMap = {
    MALWARE: "Malware detected via Google Safe Browsing",
    SOCIAL_ENGINEERING: "Phishing detected via Google Safe Browsing",
    UNWANTED_SOFTWARE: "Unwanted software detected via Google Safe Browsing",
    POTENTIALLY_HARMFUL_APPLICATION: "Potentially harmful application detected"
  };

  const uniqueThreats = [...new Set(threatTypes)];
  let total = 0;
  const reasons = [];

  uniqueThreats.forEach(type => {
    total += scoreMap[type] || 0;
    if (reasonsMap[type]) reasons.push(reasonsMap[type]);
  });

  return {
    score: total,
    uniqueThreats,
    reasons
  };
}

async function checkWithGoogleSafeBrowsing(url) {
  if (!GSB_API_KEY) throw new Error("GSB API key not found");

  const body = {
    client: {
      clientId: "gsb-tester",
      clientVersion: "1.0.0"
    },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION"
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  };

  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_API_KEY}`,
      body,
      { headers: { "Content-Type": "application/json" } }
    );

    const matches = response.data?.matches || [];
    const threatTypes = matches.map(m => m.threatType);
    const { score, uniqueThreats, reasons } = scoreThreatTypes(threatTypes);

    return {
      found: threatTypes.length > 0,
      threatTypes: uniqueThreats,
      score,
      reasons
    };
  } catch (error) {
    console.error("GSB Error:", error.message);
    return {
      found: false,
      threatTypes: [],
      score: 0,
      reasons: [],
      error: error.message
    };
  }
}

module.exports = checkWithGoogleSafeBrowsing;
