#!/usr/bin/env node

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

try {
    const commitHash = execSync("git rev-parse --short HEAD").toString().trim();

    const indexPath = path.join(__dirname, "index.html");
    let html = fs.readFileSync(indexPath, "utf8");

    html = html.replace(/<%VERSION%>/g, commitHash);

    fs.writeFileSync(indexPath, html);
} catch (error) {
    console.error("Error:", error.message);
    process.exit(1);
}
