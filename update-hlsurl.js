const fs = require("fs");
const path = require("path");

const DB_FILE = path.join(__dirname, "videos.json");

if (!fs.existsSync(DB_FILE)) {
  console.error("videos.json not found");
  process.exit(1);
}

const videos = JSON.parse(fs.readFileSync(DB_FILE, "utf-8"));

let changed = 0;

for (const v of videos) {
  if (v.hlsUrl && v.hlsUrl.endsWith("/index.m3u8")) {
    v.hlsUrl = v.hlsUrl.replace("/index.m3u8", "/master.m3u8");
    changed++;
  }
}

fs.writeFileSync(DB_FILE, JSON.stringify(videos, null, 2));

console.log(`✅ Updated ${changed} video entries to master.m3u8`);
