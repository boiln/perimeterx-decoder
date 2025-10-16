// ====================================================================
// UI LOGIC & EVENT HANDLERS
// ====================================================================
// Manages user interface, payload processing, and display
// Coordinates between decryption modules and PC computation
// ====================================================================

import { decrypt } from "./decrypt.js";
import { decryptOb } from "./decryptOb.js";
import { recomputePc } from "./pc.js";

// UI Element References
const inputPayload = document.getElementById("inputPayload");
const outputPayload = document.getElementById("outputPayload");
const uuidInput = document.getElementById("uuid");
const pcValue = document.getElementById("pcValue");
const pcText = document.querySelector(".pc-text");
const digestText = document.querySelector(".digest-text");
const statusIndicator = document.getElementById("statusIndicator");
const statusText = document.getElementById("statusText");
const digestValue = document.getElementById("digestValue");
const errorMessage = document.getElementById("errorMessage");
const errorBanner = document.getElementById("errorBanner");
const copyBtn = document.getElementById("copyBtn");
const pasteBtn = document.getElementById("pasteBtn");

let processingTimeout;

// Helper function to parse form parameters
function parseFormParams(input) {
    const params = new URLSearchParams(input);
    const result = {};
    for (const [key, value] of params.entries()) {
        result[key] = value;
    }
    return Object.keys(result).length > 0 ? result : null;
}

// Main Payload Processing Function
async function processPayload() {
    clearTimeout(processingTimeout);
    processingTimeout = setTimeout(async () => {
        try {
            const input = inputPayload.value.trim();
            let uuid = uuidInput.value.trim();

            if (!input) {
                outputPayload.value = "";
                pcValue.textContent = "----------------";
                digestValue.textContent = "--";
                pcText.style.display = "none";
                digestText.style.display = "none";
                statusText.textContent = "Ready";
                statusIndicator.className = "status-indicator";
                errorBanner.style.display = "none";
                return;
            }

            statusText.textContent = "Processing...";
            statusIndicator.className = "status-indicator";
            errorBanner.style.display = "none";

            // Check if input is form-encoded parameters
            let formParams = null;
            if (input.includes("payload=") && input.includes("&")) {
                formParams = parseFormParams(input);
                console.log("Detected form parameters:", Object.keys(formParams));

                // Auto-fill UUID from form params if not already set
                if (formParams.uuid && !uuid) {
                    uuid = formParams.uuid;
                    uuidInput.value = uuid;
                    console.log("Auto-filled UUID from form params:", uuid);
                }

                // Replace input with just the payload value
                if (formParams.payload) {
                    inputPayload.value = formParams.payload;
                    console.log("Replaced input with payload parameter");
                }
            }

            console.log("Starting payload processing ..");
            console.log("Input:", input.substring(0, 100) + " ..");
            console.log("UUID:", uuid || "(none)");

            let decryptedPayload;
            let decryptionAttempted = false;
            let inputToDecrypt = formParams ? formParams.payload : input;

            try {
                const parsedInput = JSON.parse(input);
                if (parsedInput.ob && typeof parsedInput.ob === "string") {
                    inputToDecrypt = parsedInput.ob;
                }
            } catch (e) {
                // Not JSON, use input as-is
            }

            const obResult = decryptOb(inputToDecrypt);
            console.log("ob decryption result:", obResult ? "success" : "failed");
            if (obResult) {
                decryptionAttempted = true;
                decryptedPayload = {
                    _type: "ob_decrypted",
                    decrypted: obResult.decrypted,
                    key: obResult.key,
                };
            } else {
                if (uuid) {
                    try {
                        decryptedPayload = decrypt(inputToDecrypt, uuid);
                        decryptionAttempted = true;
                    } catch (e) {
                        try {
                            decryptedPayload = JSON.parse(input);
                        } catch (jsonError) {
                            const errorDetails = e.message.includes("atob")
                                ? `Base64 decode failed. The encrypted payload may be corrupted or invalid. Original error: ${e.message}`
                                : `Decryption failed: ${e.message}`;
                            throw new Error(errorDetails);
                        }
                    }
                } else {
                    console.log("No UUID, checking if looks encrypted...");
                    const base64Chars = inputToDecrypt.replace(/[^A-Za-z0-9+/=]/g, "").length;
                    const totalChars = inputToDecrypt.length;
                    const looksEncrypted =
                        base64Chars / totalChars > 0.9 && inputToDecrypt.length > 50;

                    console.log(
                        "Looks encrypted:",
                        looksEncrypted,
                        `(${base64Chars}/${totalChars} chars)`
                    );

                    if (looksEncrypted) {
                        const uuidPattern =
                            /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
                        let foundValidDecryption = false;

                        const dummyUuid = "00000000-0000-0000-0000-000000000000";
                        try {
                            const partialDecrypt = decrypt(inputToDecrypt, dummyUuid);
                            const partialJson = JSON.stringify(partialDecrypt);

                            const potentialUuids = [
                                ...new Set(partialJson.match(uuidPattern) || []),
                            ];

                            for (const candidateUuid of potentialUuids) {
                                try {
                                    const testDecrypt = decrypt(inputToDecrypt, candidateUuid);
                                    const testJson = JSON.stringify(testDecrypt);

                                    const hasInvalidChars =
                                        /[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F\uFFFD]/.test(
                                            testJson
                                        );
                                    const isValidJson = testJson.length > 0 && !hasInvalidChars;

                                    if (isValidJson) {
                                        decryptedPayload = testDecrypt;
                                        foundValidDecryption = true;
                                        decryptionAttempted = true;
                                        uuidInput.value = candidateUuid;
                                        decryptedPayload._autoDetectedUuid = candidateUuid;
                                        break;
                                    }
                                } catch (e) {
                                    continue;
                                }
                            }
                        } catch (e) {
                            // Partial decryption failed, continue
                        }

                        if (!foundValidDecryption) {
                            try {
                                decryptedPayload = decrypt(inputToDecrypt, dummyUuid, true);
                                if (decryptedPayload._rawDecrypted) {
                                    decryptedPayload._partialDecryption = true;
                                    decryptionAttempted = true;
                                } else {
                                    decryptedPayload._partialDecryption = true;
                                    decryptionAttempted = true;
                                }
                            } catch (partialError) {
                                console.error("Partial decryption error:", partialError);
                                decryptedPayload = {
                                    _type: "needs_uuid",
                                    message:
                                        "This appears to be an encrypted request payload. Please provide a UUID to decrypt it.",
                                    encrypted: inputToDecrypt,
                                };
                            }
                        }
                    } else {
                        try {
                            decryptedPayload = JSON.parse(input);
                        } catch (jsonError) {
                            throw new Error(
                                "Unable to process input. Please provide UUID for encrypted payloads or valid JSON."
                            );
                        }
                    }
                }
            }

            console.log(
                "Decryption complete. Result type:",
                decryptedPayload._type || decryptedPayload._rawDecrypted
                    ? "raw"
                    : decryptedPayload._partialDecryption
                    ? "partial"
                    : "normal"
            );

            if (decryptedPayload._type === "ob_decrypted") {
                outputPayload.value = `Decrypted 'ob' (XOR key: ${decryptedPayload.key}):\n\n${decryptedPayload.decrypted}`;
            } else if (decryptedPayload._type === "needs_uuid") {
                outputPayload.value = `⚠️ ${
                    decryptedPayload.message
                }\n\nEncrypted payload preview:\n${decryptedPayload.encrypted.substring(0, 200)}${
                    decryptedPayload.encrypted.length > 200 ? " .." : ""
                }`;
            } else if (decryptedPayload._rawDecrypted) {
                outputPayload.value = decryptedPayload._rawDecrypted;
            } else if (decryptedPayload._partialDecryption) {
                const displayPayload = { ...decryptedPayload };
                delete displayPayload._partialDecryption;
                outputPayload.value = `⚠️ Partial Decryption (No UUID provided - showing raw/malformed output):\n\n${JSON.stringify(
                    displayPayload,
                    null,
                    4
                )}`;
            } else {
                outputPayload.value = JSON.stringify(decryptedPayload, null, 4);
            }

            // PC Computation Section
            if (
                uuid &&
                decryptedPayload._type !== "ob_decrypted" &&
                decryptedPayload._type !== "needs_uuid" &&
                !decryptedPayload._rawDecrypted &&
                !decryptedPayload._partialDecryption
            ) {
                let tag = "LxMdUmFkHTk8";
                let ft = "362";

                // Check form params first for tag and ft
                if (formParams) {
                    if (formParams.tag) {
                        tag = formParams.tag;
                        console.log("Using tag from form params:", tag);
                    }
                    if (formParams.ft) {
                        ft = String(formParams.ft);
                        console.log("Using ft from form params:", ft);
                    }
                }

                // Then check payload content (can override form params)
                if (Array.isArray(decryptedPayload) && decryptedPayload.length > 0) {
                    const firstItem = decryptedPayload[0];
                    if (firstItem && typeof firstItem === "object") {
                        if (firstItem.tag) {
                            tag = firstItem.tag;
                            console.log("Extracted tag from payload.tag:", tag);
                        }

                        if (firstItem.ft) {
                            ft = String(firstItem.ft);
                            console.log("Extracted ft from payload:", ft);
                        }
                    }
                } else if (typeof decryptedPayload === "object" && decryptedPayload !== null) {
                    if (decryptedPayload.tag) {
                        tag = decryptedPayload.tag;
                        console.log("Extracted tag from payload.tag:", tag);
                    }

                    if (decryptedPayload.ft) {
                        ft = String(decryptedPayload.ft);
                        console.log("Extracted ft from payload:", ft);
                    }
                }

                console.log("Using tag:", tag, "(from main.min.live.js constant gt)");

                try {
                    console.log("Computing PC with extracted/default values...");
                    const { pc, digest } = await recomputePc(decryptedPayload, uuid, tag, ft);
                    pcValue.textContent = pc;
                    digestValue.textContent = digest;
                    pcText.style.display = "flex";
                    digestText.style.display = "flex";
                    statusIndicator.className = "status-indicator success";
                } catch (pcError) {
                    console.error("PC computation error:", pcError);
                    pcValue.textContent = "(Error)";
                    digestValue.textContent = "(Error)";
                    pcText.style.display = "flex";
                    digestText.style.display = "flex";
                }
            } else if (decryptedPayload._type === "ob_decrypted") {
                pcValue.textContent = "----------------";
                digestValue.textContent = "--";
                pcText.style.display = "none";
                digestText.style.display = "none";
            } else if (decryptedPayload._type === "needs_uuid") {
                pcValue.textContent = "(UUID required)";
                digestValue.textContent = "(UUID required)";
                pcText.style.display = "none";
                digestText.style.display = "none";
            } else {
                pcValue.textContent = "(UUID required)";
                digestValue.textContent = "(UUID required)";
                pcText.style.display = "none";
                digestText.style.display = "none";
            }

            if (decryptedPayload._autoDetectedUuid) {
                statusText.textContent = `Auto-detected UUID: ${decryptedPayload._autoDetectedUuid.substring(
                    0,
                    18
                )}...`;
                statusIndicator.className = "status-indicator success";
            } else if (decryptedPayload._rawDecrypted) {
                statusText.textContent = "Partial Decryption (No UUID)";
                statusIndicator.className = "status-indicator warning";
            } else if (decryptedPayload._partialDecryption) {
                statusText.textContent = "Partial Decryption (UUID required)";
                statusIndicator.className = "status-indicator warning";
            } else if (decryptedPayload._type === "needs_uuid") {
                statusText.textContent = "UUID Required";
                statusIndicator.className = "status-indicator warning";
            } else if (decryptedPayload._type === "ob_decrypted") {
                statusText.textContent = "OB Decrypted";
                statusIndicator.className = "status-indicator success";
            } else {
                statusText.textContent = "Decryption Successful";
                statusIndicator.className = "status-indicator success";
            }
        } catch (error) {
            statusText.textContent = "Error";
            statusIndicator.className = "status-indicator error";
            errorMessage.textContent = error.message;
            errorBanner.style.display = "flex";
            outputPayload.value = "";
            pcValue.textContent = "----------------";
            digestValue.textContent = "--";
            pcText.style.display = "none";
            digestText.style.display = "none";
        }
    }, 300);
}

// Event Listeners
inputPayload.addEventListener("input", processPayload);
uuidInput.addEventListener("input", processPayload);

// Copy button functionality
copyBtn.addEventListener("click", async () => {
    try {
        await navigator.clipboard.writeText(outputPayload.value);
        const copyText = copyBtn.querySelector("span");
        const originalText = copyText.textContent;
        copyBtn.classList.add("success");
        copyText.textContent = "Copied!";
        setTimeout(() => {
            copyBtn.classList.remove("success");
            copyText.textContent = originalText;
        }, 1500);
    } catch (err) {
        console.error("Failed to copy:", err);
    }
});

// Paste button functionality
pasteBtn.addEventListener("click", async () => {
    try {
        const text = await navigator.clipboard.readText();
        inputPayload.value = text;
        processPayload();
        const pasteText = pasteBtn.querySelector("span");
        const originalText = pasteText.textContent;
        pasteBtn.classList.add("success");
        pasteText.textContent = "Pasted!";
        setTimeout(() => {
            pasteBtn.classList.remove("success");
            pasteText.textContent = originalText;
        }, 1500);
    } catch (err) {
        console.error("Failed to paste:", err);
    }
});

statusText.textContent = "Ready";
