// server.js (Mac friendly, huge uploads, adaptive HLS, DB safe)
// ✅ Admin login page + 2nd secret key + allowlisted computers only
// ✅ Admin Dashboard APIs: stats, list, rename, delete, rebuild thumbs, change credentials (persisted)

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");
const { nanoid } = require("nanoid");
const Busboy = require("busboy");
const http = require("http");
const session = require("express-session");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" })); // metadata only (uploads use Busboy)

// If behind proxy (nginx/cloudflare), makes req.ip accurate
app.set("trust proxy", 1);

// ---------------- Sessions (login cookie) ----------------
const isProd = process.env.NODE_ENV === "production";

app.use(
  session({
    name: "mynethub.sid",
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProd, // true only if using HTTPS in production
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  })
);

// ---------------- Paths ----------------
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, "public");
const UPLOADS = path.join(ROOT, "uploads");
const DB_FILE = path.join(ROOT, "videos.json");
const ADMIN_FILE = path.join(ROOT, "admin.json"); // persisted admin credentials

fs.mkdirSync(UPLOADS, { recursive: true });

// ---------------- Simple JSON DB ----------------
function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) return [];
    const raw = fs.readFileSync(DB_FILE, "utf-8");
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ---------------- Helpers ----------------
function safeBasename(name) {
  return path.basename(name || "upload.bin").replace(/[^\w.\-]+/g, "_");
}
function rmSafe(p) {
  try {
    if (p && fs.existsSync(p)) fs.unlinkSync(p);
  } catch {}
}
function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}
function rmDirSafe(dir) {
  try {
    if (dir && fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  } catch {}
}
function humanBytes(bytes) {
  const b = Number(bytes || 0);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let n = b;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}
function dirSizeBytes(dir) {
  let total = 0;
  if (!fs.existsSync(dir)) return 0;
  const items = fs.readdirSync(dir, { withFileTypes: true });
  for (const it of items) {
    const p = path.join(dir, it.name);
    if (it.isDirectory()) total += dirSizeBytes(p);
    else if (it.isFile()) {
      try {
        total += fs.statSync(p).size;
      } catch {}
    }
  }
  return total;
}

// ✅ Improved: includes stderr tail in error
function runFFmpeg(args) {
  return new Promise((resolve, reject) => {
    const ff = spawn("ffmpeg", args, { stdio: ["ignore", "ignore", "pipe"] });

    let stderr = "";
    ff.stderr.on("data", (d) => {
      const s = d.toString();
      stderr += s;
      process.stdout.write(s);
    });

    ff.on("error", (err) => reject(err));
    ff.on("close", (code) => {
      if (code === 0) return resolve();
      const tail = stderr.split("\n").slice(-30).join("\n");
      reject(new Error(`FFmpeg failed (exit ${code})\n\n${tail}`));
    });
  });
}

// ---------------- Admin Security ----------------
// 1) Only allow admin routes from allowlisted IPs (your computers)
// 2) Require login session

function getClientIp(req) {
  const ip = (req.ips && req.ips.length ? req.ips[0] : req.ip) || "";
  return ip.replace(/^::ffff:/, "");
}

function parseAllowedIPs() {
  const raw = String(process.env.ADMIN_ALLOWED_IPS || "").trim();
  const list = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  // Always allow localhost
  const defaults = ["127.0.0.1", "::1"];
  return Array.from(new Set([...defaults, ...list]));
}

function requireAdminIP(req, res, next) {
  const allowed = parseAllowedIPs();
  const ip = getClientIp(req);
  if (allowed.includes(ip)) return next();

  // If API request, return JSON so your dashboard JS can show error
  if (req.path.startsWith("/api/"))
    return res.status(403).json({ error: "Admin area is not allowed from this device." });

  return res.status(403).send("Admin area is not allowed from this device.");
}

function requireAdminSession(req, res, next) {
  if (req.session?.admin === true) return next();
  return res.status(401).json({ error: "Not logged in" });
}

function requireAdmin(req, res, next) {
  // helper: protect admin APIs with both checks
  return requireAdminIP(req, res, () => requireAdminSession(req, res, next));
}

// ---------------- Persisted Admin Credentials ----------------
// We store hashed password + hashed key2 in admin.json (so dashboard can change them safely)

function pbkdf2Hash(secret, salt) {
  const s = String(secret || "");
  const sl = String(salt || "");
  const buf = crypto.pbkdf2Sync(s, sl, 120000, 32, "sha256"); // 120k rounds
  return buf.toString("hex");
}

function loadAdminConfig() {
  // If admin.json exists, use it
  if (fs.existsSync(ADMIN_FILE)) {
    try {
      const raw = fs.readFileSync(ADMIN_FILE, "utf-8");
      const cfg = JSON.parse(raw);
      if (cfg && cfg.username && cfg.passHash && cfg.key2Hash && cfg.salt) return cfg;
    } catch {}
  }

  // Otherwise, bootstrap from .env
  const u = String(process.env.ADMIN_USER || "");
  const p = String(process.env.ADMIN_PASS || "");
  const k2 = String(process.env.ADMIN_KEY2 || "");
  if (!u || !p || !k2) {
    // keep empty - login will explain
    return null;
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const cfg = {
    username: u,
    salt,
    passHash: pbkdf2Hash(p, salt),
    key2Hash: pbkdf2Hash(k2, salt),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  try {
    fs.writeFileSync(ADMIN_FILE, JSON.stringify(cfg, null, 2));
  } catch {}

  return cfg;
}

function saveAdminConfig(cfg) {
  cfg.updatedAt = new Date().toISOString();
  fs.writeFileSync(ADMIN_FILE, JSON.stringify(cfg, null, 2));
}

// ---------------- Serve frontend + HLS ----------------

// HLS must stay public (or video playback breaks)
app.use(
  "/hls",
  express.static(UPLOADS, {
    setHeaders(res) {
      res.setHeader("Access-Control-Allow-Origin", "*");
    },
  })
);

// ✅ Serve admin static files (login.html + index.html)
app.use("/admin", requireAdminIP, express.static(path.join(PUBLIC, "admin")));

/**
 * ✅ IMPORTANT FIX:
 * Don't redirect /api/* to HTML login page.
 * Only protect normal site pages.
 */
function requireLoginPage(req, res, next) {
  // never redirect APIs
  if (req.path.startsWith("/api/")) return next();

  // allow admin pages + assets
  if (req.path.startsWith("/admin")) return next();

  // allow HLS files
  if (req.path.startsWith("/hls")) return next();

  // if logged in -> allow
  if (req.session?.admin === true) return next();

  // otherwise -> redirect to login page
  return res.redirect("/admin/login.html");
}

// Serve all public pages only after login middleware
app.use(requireLoginPage, express.static(PUBLIC));

// Homepage: always show login first if not logged in
app.get("/", (req, res) => {
  if (req.session?.admin === true) return res.redirect("/index.html");
  return res.redirect("/admin/login.html");
});

// ---------------- Admin Auth API (username + password + key2) ----------------
app.post("/api/admin/login", requireAdminIP, (req, res) => {
  const cfg = loadAdminConfig();
  if (!cfg)
    return res.status(500).json({
      error: "Admin creds not set. Set ADMIN_USER/ADMIN_PASS/ADMIN_KEY2 in .env (first run).",
    });

  const { username, password, key2 } = req.body || {};
  const u = String(username || "");
  const p = String(password || "");
  const k = String(key2 || "");

  if (u !== cfg.username) return res.status(401).json({ error: "Wrong credentials" });

  const passHash = pbkdf2Hash(p, cfg.salt);
  const key2Hash = pbkdf2Hash(k, cfg.salt);

  if (passHash !== cfg.passHash || key2Hash !== cfg.key2Hash) {
    return res.status(401).json({ error: "Wrong credentials" });
  }

  req.session.admin = true;
  res.json({ ok: true });
});

app.post("/api/admin/logout", requireAdminIP, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("mynethub.sid");
    res.json({ ok: true });
  });
});

// ---------------- HLS Transcoding ----------------
// Env:
//   HLS_MODE=adaptive | single
//   FFMPEG_HW=cpu | vt
async function transcodeToHLS(input, outDir) {
  ensureDir(outDir);

  const MODE = (process.env.HLS_MODE || "adaptive").toLowerCase();
  const HW = (process.env.FFMPEG_HW || "cpu").toLowerCase().trim();

  const vCodec = HW === "vt" ? "h264_videotoolbox" : "libx264";

  const hlsArgs = ["-hls_time", "6", "-hls_list_size", "0", "-hls_flags", "independent_segments"];

  // SINGLE
  if (MODE === "single") {
    const args = [
      "-y",
      "-i",
      input,
      "-c:v",
      vCodec,
      ...(vCodec === "libx264"
        ? ["-preset", "veryfast", "-crf", "20"]
        : ["-b:v", "12M", "-maxrate", "15M", "-bufsize", "30M"]),
      "-c:a",
      "aac",
      "-b:a",
      "128k",
      "-f",
      "hls",
      ...hlsArgs,
      "-hls_segment_filename",
      path.join(outDir, "seg-%03d.ts"),
      path.join(outDir, "index.m3u8"),
    ];
    await runFFmpeg(args);
    return;
  }

  // ADAPTIVE (duplicate audio per variant)
  const args = [
    "-y",
    "-i",
    input,

    "-map",
    "0:v:0",
    "-map",
    "0:v:0",
    "-map",
    "0:v:0",

    "-map",
    "0:a:0?",
    "-map",
    "0:a:0?",
    "-map",
    "0:a:0?",

    "-filter:v:0",
    "scale=w=3840:h=2160:force_original_aspect_ratio=decrease",
    "-filter:v:1",
    "scale=w=1920:h=1080:force_original_aspect_ratio=decrease",
    "-filter:v:2",
    "scale=w=1280:h=720:force_original_aspect_ratio=decrease",

    "-c:v:0",
    vCodec,
    "-c:v:1",
    vCodec,
    "-c:v:2",
    vCodec,

    ...(vCodec === "libx264"
      ? [
          "-preset",
          "veryfast",
          "-crf",
          "20",
          "-maxrate:v:0",
          "18M",
          "-bufsize:v:0",
          "36M",
          "-maxrate:v:1",
          "8M",
          "-bufsize:v:1",
          "16M",
          "-maxrate:v:2",
          "4M",
          "-bufsize:v:2",
          "8M",
        ]
      : [
          "-b:v:0",
          "16M",
          "-maxrate:v:0",
          "18M",
          "-bufsize:v:0",
          "36M",
          "-b:v:1",
          "7M",
          "-maxrate:v:1",
          "8M",
          "-bufsize:v:1",
          "16M",
          "-b:v:2",
          "3.5M",
          "-maxrate:v:2",
          "4M",
          "-bufsize:v:2",
          "8M",
        ]),

    "-c:a:0",
    "aac",
    "-b:a:0",
    "128k",
    "-c:a:1",
    "aac",
    "-b:a:1",
    "128k",
    "-c:a:2",
    "aac",
    "-b:a:2",
    "128k",

    "-var_stream_map",
    "v:0,a:0 v:1,a:1 v:2,a:2",
    "-master_pl_name",
    "master.m3u8",

    "-f",
    "hls",
    ...hlsArgs,
    "-hls_segment_filename",
    path.join(outDir, "v%v", "seg-%03d.ts"),
    path.join(outDir, "v%v", "index.m3u8"),
  ];

  await runFFmpeg(args);
}

// ---------------- Thumbnails ----------------
async function makeThumbnailFromVideo(input, outDir, seconds = 1) {
  ensureDir(outDir);
  const ss = Math.max(0, Number(seconds) || 0).toFixed(3);
  const args = ["-y", "-ss", ss, "-i", input, "-vframes", "1", "-vf", "scale=640:-1", path.join(outDir, "thumb.jpg")];
  await runFFmpeg(args);
}

async function saveThumbImage(inputImagePath, outDir) {
  ensureDir(outDir);
  const args = ["-y", "-i", inputImagePath, "-vf", "scale=640:-1", path.join(outDir, "thumb.jpg")];
  await runFFmpeg(args);
}

// Try to find a segment file we can use for thumbnails
function findThumbSourceForId(id) {
  const base = path.join(UPLOADS, id);
  const candidates = [
    path.join(base, "v2", "seg-000.ts"),
    path.join(base, "v1", "seg-000.ts"),
    path.join(base, "v0", "seg-000.ts"),
    path.join(base, "seg-000.ts"),
    path.join(base, "v2", "seg-001.ts"),
    path.join(base, "v1", "seg-001.ts"),
    path.join(base, "v0", "seg-001.ts"),
    path.join(base, "seg-001.ts"),
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  return null;
}

async function rebuildThumbForId(id, seconds) {
  const outDir = path.join(UPLOADS, id);
  const src = findThumbSourceForId(id);
  if (!src) throw new Error("No HLS segments found for thumbnails");
  const ss = Math.max(0, Number(seconds) || 0).toFixed(3);
  const args = ["-y", "-ss", ss, "-i", src, "-vframes", "1", "-vf", "scale=640:-1", path.join(outDir, "thumb.jpg")];
  await runFFmpeg(args);
}

// ---------------- Upload API (streaming) ----------------
app.post("/api/upload", (req, res) => {
  const bb = Busboy({ headers: req.headers, limits: { files: 2 } });

  const fields = {};
  let videoTmp = null;
  let videoOriginal = null;
  let thumbTmp = null;

  const pendingWrites = [];
  let aborted = false;

  function abortWith(code, msg) {
    if (aborted) return;
    aborted = true;
    rmSafe(videoTmp);
    rmSafe(thumbTmp);
    res.status(code).json({ error: msg });
  }

  req.on("aborted", () => {
    rmSafe(videoTmp);
    rmSafe(thumbTmp);
  });

  bb.on("field", (name, val) => {
    fields[name] = val;
  });

  bb.on("file", (fieldname, file, info) => {
    const original = info?.filename || "upload.bin";
    const safeName = safeBasename(original);
    const tmpName = `${Date.now()}-${safeName}`;
    const outPath = path.join(UPLOADS, tmpName);

    const ws = fs.createWriteStream(outPath);
    pendingWrites.push(
      new Promise((resolve, reject) => {
        ws.on("finish", resolve);
        ws.on("error", reject);
      })
    );

    file.on("error", (err) => ws.destroy(err));
    ws.on("error", (err) => {
      console.error("Disk write error:", err);
      abortWith(500, "Disk write error");
    });

    file.pipe(ws);

    if (fieldname === "video") {
      videoTmp = outPath;
      videoOriginal = original;
    } else if (fieldname === "thumb") {
      thumbTmp = outPath;
    }
  });

  bb.on("error", (e) => {
    console.error("Busboy error:", e);
    abortWith(400, "Upload parse error");
  });

  bb.on("finish", async () => {
    try {
      await Promise.all(pendingWrites);
      if (!videoTmp) return abortWith(400, "No video uploaded");

      const id = nanoid(10);
      const outDir = path.join(UPLOADS, id);

      await transcodeToHLS(videoTmp, outDir);

      if (thumbTmp) await saveThumbImage(thumbTmp, outDir);
      else await makeThumbnailFromVideo(videoTmp, outDir, fields.thumbTime || 1);

      rmSafe(videoTmp);
      rmSafe(thumbTmp);

      const mode = (process.env.HLS_MODE || "adaptive").toLowerCase();
      const playlist = mode === "single" ? "index.m3u8" : "master.m3u8";

      const videos = readDB();
      videos.unshift({
        id,
        title: fields.title || videoOriginal || "Untitled",
        createdAt: new Date().toISOString(),
        hlsUrl: `/hls/${id}/${playlist}`,
        thumbUrl: `/hls/${id}/thumb.jpg`,
      });
      writeDB(videos);

      res.json({ ok: true, id });
    } catch (e) {
      console.error(e);
      rmSafe(videoTmp);
      rmSafe(thumbTmp);
      res.status(500).json({ error: e.message || "Server error" });
    }
  });

  req.pipe(bb);
});

// ---------------- Public API routes ----------------
app.get("/api/videos", (req, res) => res.json(readDB()));

app.get("/api/videos/:id", (req, res) => {
  const v = readDB().find((x) => x.id === req.params.id);
  if (!v) return res.status(404).json({ error: "Not found" });
  res.json(v);
});

// ---------------- Admin Dashboard APIs ----------------

// Stats: total usage + count
app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const vids = readDB();
  let total = 0;
  for (const v of vids) total += dirSizeBytes(path.join(UPLOADS, v.id));
  res.json({
    ok: true,
    count: vids.length,
    totalBytes: total,
    totalHuman: humanBytes(total),
  });
});

// List videos with per-video folder size
app.get("/api/admin/videos", requireAdmin, (req, res) => {
  const vids = readDB();
  const out = vids.map((v) => {
    const bytes = dirSizeBytes(path.join(UPLOADS, v.id));
    return { ...v, sizeBytes: bytes, sizeHuman: humanBytes(bytes) };
  });
  res.json(out);
});

// Rename title
app.post("/api/admin/video/:id/rename", requireAdmin, (req, res) => {
  const id = String(req.params.id || "");
  const title = String(req.body?.title || "").trim();
  if (!title) return res.status(400).json({ error: "Title required" });

  const vids = readDB();
  const v = vids.find((x) => x.id === id);
  if (!v) return res.status(404).json({ error: "Not found" });

  v.title = title;
  writeDB(vids);
  res.json({ ok: true });
});

// Delete: remove folder + DB record
app.post("/api/admin/video/:id/delete", requireAdmin, (req, res) => {
  const id = String(req.params.id || "");
  const vids = readDB();
  const idx = vids.findIndex((x) => x.id === id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });

  rmDirSafe(path.join(UPLOADS, id));
  vids.splice(idx, 1);
  writeDB(vids);

  res.json({ ok: true });
});

// Rebuild thumbnails for all videos
app.post("/api/admin/rebuild-thumbs", requireAdmin, async (req, res) => {
  const seconds = Number(req.body?.seconds ?? 1);
  const vids = readDB();

  let rebuilt = 0;
  let failed = 0;

  for (const v of vids) {
    try {
      await rebuildThumbForId(v.id, seconds);
      rebuilt++;
    } catch (e) {
      failed++;
      console.error("thumb rebuild failed for", v.id, e.message);
    }
  }

  res.json({ ok: true, rebuilt, failed });
});

// Change credentials (persisted). Requires current username/pass/key2.
// After update: logs you out (safer).
app.post("/api/admin/change-credentials", requireAdminIP, async (req, res) => {
  const cfg = loadAdminConfig();
  if (!cfg)
    return res.status(500).json({
      error: "Admin creds not set. Set ADMIN_USER/ADMIN_PASS/ADMIN_KEY2 in .env (first run).",
    });

  // must be logged in to change creds
  if (req.session?.admin !== true) return res.status(401).json({ error: "Not logged in" });

  const {
    currentUsername,
    currentPassword,
    currentKey2,
    newUsername,
    newPassword,
    newKey2,
  } = req.body || {};

  const cu = String(currentUsername || "");
  const cp = String(currentPassword || "");
  const ck = String(currentKey2 || "");

  if (cu !== cfg.username) return res.status(401).json({ error: "Current credentials are wrong" });

  const passHash = pbkdf2Hash(cp, cfg.salt);
  const key2Hash = pbkdf2Hash(ck, cfg.salt);
  if (passHash !== cfg.passHash || key2Hash !== cfg.key2Hash) {
    return res.status(401).json({ error: "Current credentials are wrong" });
  }

  const nu = String(newUsername || "").trim();
  const np = String(newPassword || "");
  const nk = String(newKey2 || "");

  if (nu) cfg.username = nu;
  if (np) cfg.passHash = pbkdf2Hash(np, cfg.salt);
  if (nk) cfg.key2Hash = pbkdf2Hash(nk, cfg.salt);

  saveAdminConfig(cfg);

  req.session.destroy(() => {
    res.clearCookie("mynethub.sid");
    res.json({ ok: true, message: "Credentials updated. Please log in again." });
  });
});

// ✅ Keep your existing tool if you still want it:
app.get("/api/admin/fix-hlsurl", requireAdmin, (req, res) => {
  const videos = readDB();
  let changed = 0;

  for (const v of videos) {
    if (!v?.id) continue;
    const master = path.join(UPLOADS, v.id, "master.m3u8");
    const index = path.join(UPLOADS, v.id, "index.m3u8");

    if (fs.existsSync(master)) {
      const newUrl = `/hls/${v.id}/master.m3u8`;
      if (v.hlsUrl !== newUrl) {
        v.hlsUrl = newUrl;
        changed++;
      }
    } else if (fs.existsSync(index)) {
      const newUrl = `/hls/${v.id}/index.m3u8`;
      if (v.hlsUrl !== newUrl) {
        v.hlsUrl = newUrl;
        changed++;
      }
    }
  }

  writeDB(videos);
  res.json({ ok: true, changed });
});

// ---------------- Start server (no upload timeouts) ----------------
const PORT = process.env.PORT || 4000;
const server = http.createServer(app);

server.headersTimeout = 0;
server.requestTimeout = 0;
server.keepAliveTimeout = 0;

server.listen(PORT, () => {
  console.log(`Streaming site running on http://localhost:${PORT}`);
  console.log(`Admin allowlist: ${parseAllowedIPs().join(", ")}`);
  console.log(`HLS_MODE=${process.env.HLS_MODE || "adaptive"}  FFMPEG_HW=${process.env.FFMPEG_HW || "cpu"}`);
});
