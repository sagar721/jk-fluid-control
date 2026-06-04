const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const dist = path.join(root, "dist");
const files = ["index.html", "app.js", "styles.css", "README.md"];

function copyFile(name) {
  fs.copyFileSync(path.join(root, name), path.join(dist, name));
}

function copyDir(source, target) {
  if (!fs.existsSync(source)) return;
  fs.mkdirSync(target, { recursive: true });
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const from = path.join(source, entry.name);
    const to = path.join(target, entry.name);
    if (entry.isDirectory()) copyDir(from, to);
    else fs.copyFileSync(from, to);
  }
}

fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });

execFileSync(process.execPath, ["--check", path.join(root, "app.js")], { stdio: "inherit" });
if (!process.env.VERCEL) {
  execFileSync("python3", ["-m", "py_compile", path.join(root, "server.py")], { stdio: "inherit" });
}

for (const file of files) {
  if (file === "app.js") {
    let content = fs.readFileSync(path.join(root, file), "utf8");
    let apiUrl = process.env.VITE_API_BASE_URL || "";
    if (!apiUrl) {
      if (process.env.VERCEL) {
        // On Vercel, warn but use production Render URL as safe fallback
        console.warn("⚠️  VITE_API_BASE_URL not set in Vercel env vars. Falling back to https://jk-crm-backend.onrender.com");
        console.warn("   → Go to Vercel → Project Settings → Environment Variables and add VITE_API_BASE_URL");
        apiUrl = "https://jk-crm-backend.onrender.com";
      } else {
        // Local dev — point to local backend
        apiUrl = "http://127.0.0.1:8765";
      }
    }
    // Replace the exact quoted placeholder string — avoids partial matches in comments/keys
    content = content.replace('"VITE_API_BASE_URL"', JSON.stringify(apiUrl));
    console.log(`  API_BASE → ${apiUrl}`);
    fs.writeFileSync(path.join(dist, file), content);
  } else {
    copyFile(file);
  }
}
copyDir(path.join(root, "assets"), path.join(dist, "assets"));

const meta = {
  builtAt: new Date().toISOString(),
  files: fs.readdirSync(dist).sort()
};
fs.writeFileSync(path.join(dist, "build.json"), JSON.stringify(meta, null, 2));

console.log(`Built CRM into ${dist}`);
