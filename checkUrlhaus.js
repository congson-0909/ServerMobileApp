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
        score: 8 
      };
    } else {
      return {
        found: false,
        source: "URLhaus",
        score: 0
      };
    }
  } catch (error) {
    console.error('[URLhaus Error]', error.message);
    return {
      found: false,
      source: "URLhaus",
      score: 0,
      error: error.message
    };
  }
}

module.exports = checkUrlhaus;