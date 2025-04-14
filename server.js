const express = require("express");
const bodyParser = require("body-parser");
const analyzeStructure = require("./analyzeStructure");
const analyzeWhois = require("./analyzeWhois");

const app = express();
app.use(bodyParser.json());

app.post("/analyze", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "No URL provided" });

  const structureAnalysis = analyzeStructure(url);
  const whoisAnalysis = await analyzeWhois(url);

  const scoreTotal = structureAnalysis.score + (whoisAnalysis.score || 0);
  let finalRisk = "safe";
  if (scoreTotal >= 5) finalRisk = "dangerous";
  else if (scoreTotal >= 2) finalRisk = "suspicious";

  res.json({
    url,
    structureAnalysis,
    whoisAnalysis,
    finalRisk
  });
});

const PORT = process.env.PORT || 3003;
app.listen(PORT, () => {
  console.log(`Merged Analyzer running on port ${PORT}`);
});