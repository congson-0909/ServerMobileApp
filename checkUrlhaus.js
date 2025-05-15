const axios = require('axios');

async function checkUrlhaus(url) {
  try {
    const response = await axios.post(
      "https://urlhaus-api.abuse.ch/v1/url/",
      new URLSearchParams({ url }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const { query_status, url: matchedUrl } = response.data;

    if (query_status === "ok" && matchedUrl) {
      return {
        found: true,
        source: "URLhaus",
        score: 8,
        reasons: ["Malware detected via URLhaus"]
      };
    } else {
      return {
        found: false,
        source: "URLhaus",
        score: 0,
        reasons: []
      };
    }
  } catch (error) {
    console.error('[URLhaus Error]', error.message);
    return {
      found: false,
      source: "URLhaus",
      score: 0,
      reasons: [],
      error: error.message
    };
  }
}

module.exports = checkUrlhaus;
