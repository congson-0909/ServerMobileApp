const axios = require("axios");

const GSB_API_KEY = "AIzaSyBd_EX5XKA-5PqIUF0do3qW3K-ktL8PJJc";

function scoreThreatTypes(threatTypes) {
  const scoreMap = {
    MALWARE: 8,
    SOCIAL_ENGINEERING: 8,
    UNWANTED_SOFTWARE: 4,
    POTENTIALLY_HARMFUL_APPLICATION: 4
  };

  const uniqueThreats = [...new Set(threatTypes)];
  let total = 0;

  uniqueThreats.forEach(type => {
    total += scoreMap[type] || 0;
  });

  return {
    score: total,
    uniqueThreats
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
    const { score, uniqueThreats } = scoreThreatTypes(threatTypes);

    return {
      found: threatTypes.length > 0,
      threatTypes: uniqueThreats,
      score
    };
  } catch (error) {
    console.error("GSB Error:", error.message);
    return {
      found: false,
      threatTypes: [],
      score: 0,
      error: error.message
    };
  }
}

module.exports = checkWithGoogleSafeBrowsing;
