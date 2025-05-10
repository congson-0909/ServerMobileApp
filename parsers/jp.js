const puppeteer = require("puppeteer");

async function getWhoisJP(domain) {
  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--disable-setuid-sandbox"]
  });

  const page = await browser.newPage();
  await page.goto("https://whois.jprs.jp/", { waitUntil: "domcontentloaded" });

  // Gửi form tìm kiếm
  await page.select('select[name="type"]', "DOMAIN");
  await page.type('input[name="key"]', domain);
  await Promise.all([
    page.click('input[type="submit"]'),
    page.waitForNavigation({ waitUntil: "domcontentloaded" })
  ]);

  const rawText = await page.$eval("pre", el => el.innerText);
  await browser.close();

  // Phân tích nội dung tiếng Nhật
  const result = {};
  const lines = rawText.split("\n");
  for (const line of lines) {
    const [key, ...rest] = line.split("]");
    if (key && rest.length) {
      result[key.trim() + "]"] = rest.join("]").trim();
    }
  }

  // Map dữ liệu
  const registeredOnJP = result["[登録年月日]"] || null;
  const registrantJP = result["f. [組織名]"] || "";
  const registrantEN = result["g. [Organization]"] || "";
  const country = "JP";

  // Convert ngày
  let creationDate = null;
  if (registeredOnJP && /^\d{4}\/\d{2}\/\d{2}$/.test(registeredOnJP)) {
    creationDate = new Date(registeredOnJP).toISOString();
  }

  return {
    registeredOn: registeredOnJP,
    registrant: registrantEN || registrantJP,
    country,
    raw: rawText,
    creationDate
  };
}

module.exports = getWhoisJP;