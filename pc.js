// ====================================================================
// PC (CHECKSUM) COMPUTATION
// ====================================================================
// Computes the 16-digit 'pc' checksum for PerimeterX payloads
// Algorithm: pc = transform( HMAC_MD5( serialize(payload), "uuid:tag:ft" ) )
//
// Steps:
// 1. Serialize payload P using custom serializer (preserves key insertion order!)
// 2. Form HMAC key K = "uuid:tag:ft" (colon-separated)
// 3. Compute HMAC-MD5 digest D = HMAC_MD5(serialized, K) → 32 hex chars
// 4. Transform digest to 16-digit PC:
//    - Extract all decimal digits (0-9) → digits string
//    - For each hex letter (a-f), append (charCode % 10) → mapped string
//      (a=97%10=7, b=98%10=8, c=99%10=9, d=100%10=0, e=101%10=1, f=102%10=2)
//    - Concatenate: combo = digits + mapped (32 chars total)
//    - Take every 2nd character (indices 0,2,4,...,30) → 16-digit PC
//
// CRITICAL: Key order preservation!
// - customJsonStringify MUST preserve object key insertion order
// - JavaScript objects maintain insertion order (ES2015+)
// - Never sort keys or the PC will be wrong
// - null values serialize as "null", undefined values serialize as "null"
// ====================================================================

function customJsonStringify(payload) {
    function t(e) {
        return typeof e;
    }

    const G = {
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
        "\v": "\\v",
        '"': '\\"',
        "\\": "\\\\",
    };

    function W(t) {
        const e = G[t];
        return e || "\\u" + ("0000" + t.charCodeAt(0).toString(16)).slice(-4);
    }

    const F =
        /[\\\"\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g;

    function L(t) {
        F.lastIndex = 0;
        return '"' + (F.test(t) ? t.replace(F, W) : t) + '"';
    }

    function j(e) {
        switch (t(e)) {
            case "undefined":
                return "null";
            case "boolean":
                return String(e);
            case "number":
                const r = String(e);
                return "NaN" === r || "Infinity" === r ? "null" : r;
            case "string":
                return L(e);
        }
        if (null === e || e instanceof RegExp) {
            return "null";
        }
        if (e instanceof Date) {
            return [
                '"',
                e.getFullYear(),
                "-",
                e.getMonth() + 1,
                "-",
                e.getDate(),
                "T",
                e.getHours(),
                ":",
                e.getMinutes(),
                ":",
                e.getSeconds(),
                ".",
                e.getMilliseconds(),
                '"',
            ].join("");
        }
        if (e instanceof Array) {
            const n = ["["];
            for (let a = 0; a < e.length; a++) {
                n.push(j(e[a]) || '"undefined"', ",");
            }
            n[n.length > 1 ? n.length - 1 : n.length] = "]";
            return n.join("");
        }
        const n = ["{"];
        for (const o in e) {
            if (e.hasOwnProperty(o) && undefined !== e[o]) {
                n.push(L(o), ":", j(e[o]) || '"undefined"', ",");
            }
        }
        n[n.length > 1 ? n.length - 1 : n.length] = "}";
        return n.join("");
    }

    return j(payload);
}

function md5Hmac(message, key) {
    function md5cycle(x, k) {
        let a = x[0],
            b = x[1],
            c = x[2],
            d = x[3];
        a = ff(a, b, c, d, k[0], 7, -680876936);
        d = ff(d, a, b, c, k[1], 12, -389564586);
        c = ff(c, d, a, b, k[2], 17, 606105819);
        b = ff(b, c, d, a, k[3], 22, -1044525330);
        a = ff(a, b, c, d, k[4], 7, -176418897);
        d = ff(d, a, b, c, k[5], 12, 1200080426);
        c = ff(c, d, a, b, k[6], 17, -1473231341);
        b = ff(b, c, d, a, k[7], 22, -45705983);
        a = ff(a, b, c, d, k[8], 7, 1770035416);
        d = ff(d, a, b, c, k[9], 12, -1958414417);
        c = ff(c, d, a, b, k[10], 17, -42063);
        b = ff(b, c, d, a, k[11], 22, -1990404162);
        a = ff(a, b, c, d, k[12], 7, 1804603682);
        d = ff(d, a, b, c, k[13], 12, -40341101);
        c = ff(c, d, a, b, k[14], 17, -1502002290);
        b = ff(b, c, d, a, k[15], 22, 1236535329);
        a = gg(a, b, c, d, k[1], 5, -165796510);
        d = gg(d, a, b, c, k[6], 9, -1069501632);
        c = gg(c, d, a, b, k[11], 14, 643717713);
        b = gg(b, c, d, a, k[0], 20, -373897302);
        a = gg(a, b, c, d, k[5], 5, -701558691);
        d = gg(d, a, b, c, k[10], 9, 38016083);
        c = gg(c, d, a, b, k[15], 14, -660478335);
        b = gg(b, c, d, a, k[4], 20, -405537848);
        a = gg(a, b, c, d, k[9], 5, 568446438);
        d = gg(d, a, b, c, k[14], 9, -1019803690);
        c = gg(c, d, a, b, k[3], 14, -187363961);
        b = gg(b, c, d, a, k[8], 20, 1163531501);
        a = gg(a, b, c, d, k[13], 5, -1444681467);
        d = gg(d, a, b, c, k[2], 9, -51403784);
        c = gg(c, d, a, b, k[7], 14, 1735328473);
        b = gg(b, c, d, a, k[12], 20, -1926607734);
        a = hh(a, b, c, d, k[5], 4, -378558);
        d = hh(d, a, b, c, k[8], 11, -2022574463);
        c = hh(c, d, a, b, k[11], 16, 1839030562);
        b = hh(b, c, d, a, k[14], 23, -35309556);
        a = hh(a, b, c, d, k[1], 4, -1530992060);
        d = hh(d, a, b, c, k[4], 11, 1272893353);
        c = hh(c, d, a, b, k[7], 16, -155497632);
        b = hh(b, c, d, a, k[10], 23, -1094730640);
        a = hh(a, b, c, d, k[13], 4, 681279174);
        d = hh(d, a, b, c, k[0], 11, -358537222);
        c = hh(c, d, a, b, k[3], 16, -722521979);
        b = hh(b, c, d, a, k[6], 23, 76029189);
        a = hh(a, b, c, d, k[9], 4, -640364487);
        d = hh(d, a, b, c, k[12], 11, -421815835);
        c = hh(c, d, a, b, k[15], 16, 530742520);
        b = hh(b, c, d, a, k[2], 23, -995338651);
        a = ii(a, b, c, d, k[0], 6, -198630844);
        d = ii(d, a, b, c, k[7], 10, 1126891415);
        c = ii(c, d, a, b, k[14], 15, -1416354905);
        b = ii(b, c, d, a, k[5], 21, -57434055);
        a = ii(a, b, c, d, k[12], 6, 1700485571);
        d = ii(d, a, b, c, k[3], 10, -1894986606);
        c = ii(c, d, a, b, k[10], 15, -1051523);
        b = ii(b, c, d, a, k[1], 21, -2054922799);
        a = ii(a, b, c, d, k[8], 6, 1873313359);
        d = ii(d, a, b, c, k[15], 10, -30611744);
        c = ii(c, d, a, b, k[6], 15, -1560198380);
        b = ii(b, c, d, a, k[13], 21, 1309151649);
        a = ii(a, b, c, d, k[4], 6, -145523070);
        d = ii(d, a, b, c, k[11], 10, -1120210379);
        c = ii(c, d, a, b, k[2], 15, 718787259);
        b = ii(b, c, d, a, k[9], 21, -343485551);
        x[0] = add32(a, x[0]);
        x[1] = add32(b, x[1]);
        x[2] = add32(c, x[2]);
        x[3] = add32(d, x[3]);
    }

    function cmn(q, a, b, x, s, t) {
        a = add32(add32(a, q), add32(x, t));
        return add32((a << s) | (a >>> (32 - s)), b);
    }

    function ff(a, b, c, d, x, s, t) {
        return cmn((b & c) | (~b & d), a, b, x, s, t);
    }

    function gg(a, b, c, d, x, s, t) {
        return cmn((b & d) | (c & ~d), a, b, x, s, t);
    }

    function hh(a, b, c, d, x, s, t) {
        return cmn(b ^ c ^ d, a, b, x, s, t);
    }

    function ii(a, b, c, d, x, s, t) {
        return cmn(c ^ (b | ~d), a, b, x, s, t);
    }

    function md51(s) {
        const n = s.length;
        const state = [1732584193, -271733879, -1732584194, 271733878];
        let i;
        for (i = 64; i <= s.length; i += 64) {
            md5cycle(state, md5blk(s.substring(i - 64, i)));
        }
        s = s.substring(i - 64);
        const tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (i = 0; i < s.length; i++) {
            tail[i >> 2] |= s.charCodeAt(i) << (i % 4 << 3);
        }
        tail[i >> 2] |= 0x80 << (i % 4 << 3);
        if (i > 55) {
            md5cycle(state, tail);
            for (i = 0; i < 16; i++) tail[i] = 0;
        }
        tail[14] = n * 8;
        md5cycle(state, tail);
        return state;
    }

    function md5blk(s) {
        const md5blks = [];
        for (let i = 0; i < 64; i += 4) {
            md5blks[i >> 2] =
                s.charCodeAt(i) +
                (s.charCodeAt(i + 1) << 8) +
                (s.charCodeAt(i + 2) << 16) +
                (s.charCodeAt(i + 3) << 24);
        }
        return md5blks;
    }

    function rhex(n) {
        let s = "";
        for (let j = 0; j < 4; j++) {
            const highNibble = ((n >> (j * 8 + 4)) & 0x0f).toString(16);
            const lowNibble = ((n >> (j * 8)) & 0x0f).toString(16);
            s += highNibble + lowNibble;
        }
        return s;
    }

    function hex(x) {
        for (let i = 0; i < x.length; i++) {
            x[i] = rhex(x[i]);
        }
        return x.join("");
    }

    function add32(a, b) {
        return (a + b) & 0xffffffff;
    }

    const blockSize = 64;
    let keyBytes = [];
    for (let i = 0; i < key.length; i++) {
        keyBytes.push(key.charCodeAt(i));
    }

    if (keyBytes.length > blockSize) {
        const hash = md51(key);
        keyBytes = [];
        for (let i = 0; i < hash.length; i++) {
            for (let j = 0; j < 4; j++) {
                keyBytes.push((hash[i] >> (j * 8)) & 0xff);
            }
        }
    }

    while (keyBytes.length < blockSize) {
        keyBytes.push(0);
    }

    const oKeyPad = keyBytes.map((b) => b ^ 0x5c);
    const iKeyPad = keyBytes.map((b) => b ^ 0x36);

    const innerStr = String.fromCharCode(...iKeyPad) + message;
    const innerHash = md51(innerStr);

    let innerHashBytes = [];
    for (let i = 0; i < innerHash.length; i++) {
        for (let j = 0; j < 4; j++) {
            innerHashBytes.push((innerHash[i] >> (j * 8)) & 0xff);
        }
    }

    const outerStr = String.fromCharCode(...oKeyPad) + String.fromCharCode(...innerHashBytes);
    const outerHash = md51(outerStr);

    return hex(outerHash);
}

function derivePcFromDigest(hex32) {
    let digits = "";
    let mapped = "";

    for (const ch of hex32) {
        if (/\d/.test(ch)) {
            digits += ch;
        } else {
            mapped += String(ch.charCodeAt(0) % 10);
        }
    }

    const combo = digits + mapped;

    let pc = "";
    for (let i = 0; i < 32; i += 2) {
        pc += combo[i];
    }

    return pc;
}

export async function recomputePc(payload, uuid, tag, ft) {
    console.log("\n=== PC Computation Started ===");
    console.log("UUID:", uuid);
    console.log("Tag:", tag);
    console.log("FT:", ft);

    const serialized = customJsonStringify(payload);
    console.log("Serialized length:", serialized.length);
    console.log("Serialized (first 200 chars):", serialized.substring(0, 200));

    const key = `${uuid}:${tag}:${ft}`;
    console.log("HMAC Key:", key);

    const digest = md5Hmac(serialized, key);
    console.log("MD5-HMAC Digest:", digest);

    const pc = derivePcFromDigest(digest);
    console.log("Derived PC:", pc);
    console.log("=== PC Computation Complete ===\n");

    return { pc, digest };
}
