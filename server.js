const express = require("express");
const bodyParser = require("body-parser");
const analyze = require("./analyze"); 

const app = express();
app.use(bodyParser.json());

app.post("/analyze", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "No URL provided" });

  try {
    const result = await analyze(url);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Analysis failed", details: err.message });
  }
});

const PORT = process.env.PORT || 3003;
app.listen(PORT, () => {
  console.log(`Merged Analyzer running on port ${PORT}`);
});