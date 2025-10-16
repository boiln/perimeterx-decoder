// ====================================================================
// RESPONSE PAYLOAD DECRYPTION (OB field - XOR-based)
// ====================================================================
// Decrypts 'ob' fields in PerimeterX responses (e.g., CAPTCHA responses)
// Encryption: XOR with key (1-255) → base64
// Auto-detects XOR key by brute force (looks for "o~~~~" pattern)
// No UUID required - standalone decryption
// ====================================================================

export function decryptOb(rawOb, key = null) {
    try {
        const invalidBase64Pattern = /[^+/=0-9A-Za-z]/;
        const invalidPaddingPattern = /=[^=]|={3}/;

        if (
            invalidBase64Pattern.test(rawOb) ||
            (rawOb.includes("=") && invalidPaddingPattern.test(rawOb))
        ) {
            return null;
        }

        const paddingNeeded = (4 - (rawOb.length % 4)) % 4;
        const rawObPadded = rawOb + "=".repeat(paddingNeeded);

        const raw = Uint8Array.from(atob(rawObPadded), (c) => c.charCodeAt(0));

        if (key !== null) {
            const decrypted = Array.from(raw)
                .map((b) => String.fromCharCode(b ^ key))
                .join("");
            return { decrypted, key };
        }

        for (let k = 1; k < 256; k++) {
            const decrypted = Array.from(raw)
                .map((b) => String.fromCharCode(b ^ k))
                .join("");

            if (
                decrypted.startsWith("o") &&
                decrypted.includes("~~~~") &&
                decrypted.split("").every((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127)
            ) {
                return { decrypted, key: k };
            }
        }

        const decrypted0 = Array.from(raw)
            .map((b) => String.fromCharCode(b ^ 0))
            .join("");
        if (
            decrypted0.startsWith("o") &&
            decrypted0.includes("~~~~") &&
            decrypted0.split("").every((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127)
        ) {
            return { decrypted: decrypted0, key: 0 };
        }

        return null;
    } catch (e) {
        return null;
    }
}
