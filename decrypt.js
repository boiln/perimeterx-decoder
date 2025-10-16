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

    for (const idx of removeIdx) {
        base64Str = base64Str.slice(0, idx) + base64Str.slice(idx + 1);
    }

    console.log("After removal length:", base64Str.length);

    const beforeClean = base64Str;
    base64Str = base64Str.replace(/[^A-Za-z0-9+/=]/g, "");

    if (beforeClean !== base64Str) {
        const invalidChars = beforeClean.match(/[^A-Za-z0-9+/=]/g);
        console.log("⚠️ Cleaned", invalidChars.length, "invalid chars:", invalidChars);
    }

    const paddingNeeded = (4 - (base64Str.length % 4)) % 4;
    if (paddingNeeded > 0) {
        base64Str += "=".repeat(paddingNeeded);
    }

    console.log("✅ Final base64 ready, length:", base64Str.length);

    let buf;
    let decodeFailed = false;
    try {
        buf = Uint8Array.from(atob(base64Str), (c) => c.charCodeAt(0));
    } catch (atobError) {
        console.log("⚠️ atob failed:", atobError.message);
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
