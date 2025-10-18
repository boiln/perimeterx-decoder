// ====================================================================
// RESPONSE PAYLOAD DECRYPTION (OB field - XOR-based)
// ====================================================================
// Decrypts 'ob' fields in PerimeterX responses
//
// 1. Validate base64 format
// 2. Add padding if needed to make length divisible by 4
// 3. Base64 decode to get XOR'd bytes
// 4. XOR every byte with the key to recover original plaintext
//
// No UUID Required: Unlike request decryption, this is standalone
// The XOR key is much simpler and can be brute-forced quickly
//
// Returns: {decrypted: string, key: number} or null if decryption fails
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

        return null;
    } catch (e) {
        return null;
    }
}
