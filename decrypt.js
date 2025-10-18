// ====================================================================
// REQUEST PAYLOAD DECRYPTION (UUID-based encryption)
// ====================================================================
// Decrypts encrypted request payloads sent to PerimeterX servers
// Encryption: XOR(50) → percent-encode → base64 → salt interleaving
// Requires: UUID for salt removal
// ====================================================================

function jt(str, key) {
    let r = "";
    for (let i = 0; i < str.length; i++) {
        r += String.fromCharCode(str.charCodeAt(i) ^ key);
    }
    return r;
}

function computeMapping(o, e, uuid) {
    const b64 = btoa(uuid);
    const v = jt(b64, 10);

    let p = -1;
    for (let g = 0; g < o.length; g++) {
        const y = Math.floor(g / v.length + 1);
        const b = g >= v.length ? g % v.length : g;
        const T = v.charCodeAt(b) * v.charCodeAt(y);
        if (T > p) p = T;
    }

    const m = [];
    for (let E = 0; E < o.length; E++) {
        const S = Math.floor(E / v.length) + 1;
        const I = E % v.length;
        let A = v.charCodeAt(I) * v.charCodeAt(S);

        if (A >= e) {
            A = Math.floor((A / p) * (e - 1));
        }
        while (m.indexOf(A) !== -1) {
            A++;
        }
        m.push(A);
    }

    return m.sort((a, b) => a - b);
}

export function decrypt(encrypted, uuid, allowPartial = false) {
    const o = "G^S}DNK8DNa>D`K}GK77";
    const L = o.length;

    const origLen = encrypted.length - L;
    const mapping = computeMapping(o, origLen, uuid);
    let base64Str = encrypted;
    const removeIdx = mapping.map((x) => x - 1).sort((a, b) => b - a);

    console.log("Decrypt Debug:");
    console.log("Original length:", encrypted.length);
    console.log("Expected base64 length after removal:", origLen);
    console.log("Number of chars to remove:", removeIdx.length);
    console.log("Salt positions (1-indexed, first 5):", mapping.slice(0, 5));
    console.log("Salt positions (0-indexed, first 5 after sort desc):", removeIdx.slice(0, 5));

    // Show what characters we're actually removing
    const charsToRemove = removeIdx.slice(0, 10).map((idx) => ({
        pos: idx,
        char: encrypted[idx] || "OUT_OF_BOUNDS",
        code: encrypted.charCodeAt(idx) || -1,
    }));
    console.log("Characters at removal positions (first 10):", charsToRemove);

    for (const idx of removeIdx) {
        if (idx >= 0 && idx < base64Str.length) {
            base64Str = base64Str.slice(0, idx) + base64Str.slice(idx + 1);
        }
    }

    console.log("After removal length:", base64Str.length);

    // Show a sample of what we have after salt removal
    console.log("After salt removal (first 100 chars):", base64Str.substring(0, 100));
    console.log("After salt removal (last 50 chars):", base64Str.substring(base64Str.length - 50));

    const beforeClean = base64Str;

    // CRITICAL: Replace spaces with + (form encoding converts + to space)
    base64Str = base64Str.replace(/ /g, "+");

    // Clean any remaining invalid characters
    base64Str = base64Str.replace(/[^A-Za-z0-9+/=]/g, "");

    if (beforeClean !== base64Str) {
        const invalidChars = beforeClean.match(/[^A-Za-z0-9+/=]/g);
        const invalidPositions = [];
        for (let i = 0; i < beforeClean.length; i++) {
            if (!/[A-Za-z0-9+/=]/.test(beforeClean[i])) {
                invalidPositions.push({
                    pos: i,
                    char: beforeClean[i],
                    code: beforeClean.charCodeAt(i),
                });
            }
        }
        console.log("⚠️ Cleaned", invalidChars.length, "invalid chars:", invalidChars);
        console.log("⚠️ Invalid char positions (first 10):", invalidPositions.slice(0, 10));
    }

    const paddingNeeded = (4 - (base64Str.length % 4)) % 4;
    if (paddingNeeded > 0) {
        console.log(`Adding ${paddingNeeded} padding char(s)`);
        base64Str += "=".repeat(paddingNeeded);
    }

    console.log("✅ Final base64 ready, length:", base64Str.length);
    console.log("Final base64 (first 100):", base64Str.substring(0, 100));
    console.log("Final base64 (last 50):", base64Str.substring(base64Str.length - 50));

    let buf;
    let decodeFailed = false;
    try {
        buf = Uint8Array.from(atob(base64Str), (c) => c.charCodeAt(0));
    } catch (atobError) {
        console.log("⚠️ atob failed:", atobError.message);
        console.log("Base64 length:", base64Str.length, "mod 4:", base64Str.length % 4);

        // Try to find where the base64 is invalid
        console.log("Testing base64 validity in chunks...");
        for (let i = 0; i < Math.min(5, Math.floor(base64Str.length / 100)); i++) {
            const chunk = base64Str.substring(i * 100, (i + 1) * 100);
            try {
                atob(chunk.padEnd(Math.ceil(chunk.length / 4) * 4, "="));
                console.log(`✓ Chunk ${i} (${i * 100}-${(i + 1) * 100}) is valid`);
            } catch (e) {
                console.log(`✗ Chunk ${i} (${i * 100}-${(i + 1) * 100}) is INVALID:`, chunk);
            }
        }

        decodeFailed = true;

        if (allowPartial) {
            console.log("Attempting byte-by-byte decode...");
            const bytes = [];
            for (let i = 0; i < base64Str.length; i += 4) {
                const chunk = base64Str.substring(i, Math.min(i + 4, base64Str.length));
                try {
                    const decoded = atob(chunk.padEnd(4, "="));
                    for (let j = 0; j < decoded.length; j++) {
                        bytes.push(decoded.charCodeAt(j));
                    }
                } catch (e) {
                    // Skip this chunk
                }
            }
            buf = new Uint8Array(bytes);
            console.log(`Decoded ${bytes.length} bytes from partial decode`);
        } else {
            throw atobError;
        }
    }

    const latin1 = Array.from(buf)
        .map((b) => String.fromCharCode(b))
        .join("");

    let pct = "";
    for (let i = 0; i < latin1.length; i++) {
        const hex = latin1.charCodeAt(i).toString(16).toUpperCase().padStart(2, "0");
        pct += "%" + hex;
    }

    let xoredJson;
    try {
        xoredJson = decodeURIComponent(pct);
    } catch (e) {
        const bytes = [];
        for (let i = 0; i < pct.length; i++) {
            if (pct[i] === "%" && i + 2 < pct.length) {
                const hex = pct.substring(i + 1, i + 3);
                bytes.push(parseInt(hex, 16));
                i += 2;
            } else {
                bytes.push(pct.charCodeAt(i));
            }
        }
        xoredJson = new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
    }

    let jsonStr = "";
    for (let i = 0; i < xoredJson.length; i++) {
        jsonStr += String.fromCharCode(xoredJson.charCodeAt(i) ^ 50);
    }

    if (allowPartial) {
        try {
            return JSON.parse(jsonStr);
        } catch (e) {
            console.log("JSON parse failed, returning raw decrypted string");
            return {
                _rawDecrypted: jsonStr,
                _parseError: e.message,
                _note: "Partial decryption - wrong UUID produces malformed output",
            };
        }
    }

    return JSON.parse(jsonStr);
}
