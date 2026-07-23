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

// ====================================================================
// HELPER FUNCTIONS
// ====================================================================

function parseFormParams(input) {
    const params = new URLSearchParams(input);
    const result = {};

    for (const [key, value] of params.entries()) {
        result[key] = value;
    }

    if (Object.keys(result).length === 0) {
        return null;
    }

    return result;
}

function looksLikeEncrypted(input) {
    const base64Chars = input.replace(/[^A-Za-z0-9+/=]/g, "").length;
    const totalChars = input.length;

    return base64Chars / totalChars > 0.9 && input.length > 50;
}

function resetUI() {
    outputPayload.value = "";
    pcValue.textContent = "----------------";
    digestValue.textContent = "--";
    pcText.style.display = "none";
    digestText.style.display = "none";
    statusText.textContent = "Ready";
    statusIndicator.className = "status-indicator";
    errorBanner.style.display = "none";
}

function showError(error) {
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

function setStatus(text, type) {
    statusText.textContent = text;
    statusIndicator.className = `status-indicator ${type}`;
}

function hidePcDisplay() {
    pcText.style.display = "none";
    digestText.style.display = "none";
}

function showPcDisplay() {
    pcText.style.display = "flex";
    digestText.style.display = "flex";
}

// ====================================================================
// DECRYPTION LOGIC
// ====================================================================

function tryObDecryption(input) {
    const result = decryptOb(input);

    if (!result) {
        return null;
    }

    return {
        _type: "ob_decrypted",
        decrypted: result.decrypted,
        key: result.key,
    };
}

function tryUuidDecryption(input, uuid, originalInput) {
    try {
        return decrypt(input, uuid);
    } catch (e) {
        try {
            return JSON.parse(originalInput);
        } catch (jsonError) {
            const errorDetails = e.message.includes("atob")
            ? `Base64 decode failed. The encrypted payload may be corrupted or invalid. Original error: ${e.message}`
            : `Decryption failed: ${e.message}`;

            throw new Error(errorDetails);
        }
    }
}

function tryAutoDetectUuid(input) {
    const uuidPattern =
        /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
    const dummyUuid = "00000000-0000-0000-0000-000000000000";

    try {
        const partialDecrypt = decrypt(input, dummyUuid);
        const partialJson = JSON.stringify(partialDecrypt);
        const potentialUuids = [... new Set(partialJson.match (uuidPattern) || [])];

        for (const candidateUuid of potentialUuids) {
            try {
                const testDecrypt = decrypt(input, candidateUuid);
                const testJson = JSON.stringify(testDecrypt);
                const hasInvalidChars =
                    /[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F\uFFFD]/.test(testJson);

                if (testJson.length > 0 && !hasInvalidChars) {
                    testDecrypt._autoDetectedUuid = candidateUuid;

                    return testDecrypt;
                }
            } catch (e) {
                continue;
            }
        }
    } catch (e) {
        // Partial decryption failed
    }

    return null;
}

function tryPartialDecryption(input) {
    const dummyUuid = "00000000-0000-0000-0000-000000000000";

    try {
        const result = decrypt(input, dummyUuid, true);

        result._partialDecryption = true;

        return result;
    } catch (e) {
        console.error("Partial decryption error:", e);

        return {
            _type: "needs_uuid",
            message:
            "This appears to be an encrypted request payload. Please provide a UUID to decrypt it.",
            encrypted: input,
        };
    }
}

function decryptPayload(input, uuid, originalInput) {
    // Try OB decryption first
    const obResult = tryObDecryption(input);

    if (obResult) {
        console.log("ob decryption result: success");

        return obResult;
    }

    console.log("ob decryption result: failed");

    // If we have a UUID, use it
    if (uuid) {
        return tryUuidDecryption(input, uuid, originalInput);
    }

    // No UUID - check if it looks encrypted
    console.log("No UUID, checking if looks encrypted...");

    if (!looksLikeEncrypted(input)) {
        console.log("Looks encrypted: false");

        try {
            return JSON.parse(originalInput);
        } catch (jsonError) {
            throw new Error(
                "Unable to process input. Please provide UUID for encrypted payloads or valid JSON.",
            );
        }
    }

    console.log("Looks encrypted: true");

    // Try auto-detecting UUID
    const autoDetected = tryAutoDetectUuid(input);

    if (autoDetected) {
        uuidInput.value = autoDetected._autoDetectedUuid;

        return autoDetected;
    }

    // Fall back to partial decryption
    return tryPartialDecryption(input);
}

// ====================================================================
// OUTPUT DISPLAY
// ====================================================================

function formatOutput(payload) {
    if (payload._type === "ob_decrypted") {
        return `Decrypted 'ob' (XOR key: ${payload.key}):\n\n${payload.decrypted}`;
    }

    if (payload._type === "needs_uuid") {
        const preview = payload.encrypted.substring(0, 200);
        const suffix = payload.encrypted.length > 200 ? " .." : "";

        return `⚠️ ${payload.message}\n\nEncrypted payload preview:\n${preview}${suffix}`;
    }

    if (payload._rawDecrypted) {
        return payload._rawDecrypted;
    }

    if (payload._partialDecryption) {
        const displayPayload = { ... payload };

        delete displayPayload._partialDecryption;

        return `⚠️ Partial Decryption (No UUID provided - showing raw/malformed output):\n\n${JSON.stringify(displayPayload, null, 4)}`;
    }

    return JSON.stringify(payload, null, 4);
}

function updateStatusFromPayload(payload) {
    if (payload._autoDetectedUuid) {
        setStatus(
            `Auto-detected UUID: ${payload._autoDetectedUuid.substring(0, 18)}...`,
            "success",
        );

        return;
    }

    if (payload._rawDecrypted) {
        setStatus("Partial Decryption (No UUID)", "warning");

        return;
    }

    if (payload._partialDecryption) {
        setStatus("Partial Decryption (UUID required)", "warning");

        return;
    }

    if (payload._type === "needs_uuid") {
        setStatus("UUID Required", "warning");

        return;
    }

    if (payload._type === "ob_decrypted") {
        setStatus("OB Decrypted", "success");

        return;
    }

    setStatus("Decryption Successful", "success");
}

// ====================================================================
// PC COMPUTATION
// ====================================================================

function extractTagAndFt(payload, formParams) {
    let tag = "LxMdUmFkHTk8";
    let ft = "362";

    if (formParams?.tag) {
        tag = formParams.tag;
        console.log("Using tag from form params:", tag);
    }

    if (formParams?.ft) {
        ft = String(formParams.ft);
        console.log("Using ft from form params:", ft);
    }

    const source =
        Array.isArray(payload) && payload.length > 0 ? payload[0] : payload;

    if (source && typeof source === "object") {
        if (source.tag) {
            tag = source.tag;
            console.log("Extracted tag from payload.tag:", tag);
        }

        if (source.ft) {
            ft = String(source.ft);
            console.log("Extracted ft from payload:", ft);
        }
    }

    return { tag, ft };
}

function canComputePc(payload, uuid) {
    if (!uuid) return false;
    if (payload._type === "ob_decrypted") return false;
    if (payload._type === "needs_uuid") return false;
    if (payload._rawDecrypted) return false;
    if (payload._partialDecryption) return false;

    return true;
}

async function computeAndDisplayPc(payload, uuid, formParams) {
    if (!canComputePc(payload, uuid)) {
        updatePcDisplayForSpecialCases(payload, uuid);

        return;
    }

    const { tag, ft } = extractTagAndFt(payload, formParams);

    console.log("Using tag:", tag, "(from main.min.live.js constant gt)");

    try {
        console.log("Computing PC with extracted/default values...");
        const { pc, digest } = await recomputePc(payload, uuid, tag, ft);

        pcValue.textContent = pc;
        digestValue.textContent = digest;
        showPcDisplay();
        statusIndicator.className = "status-indicator success";
    } catch (pcError) {
        console.error("PC computation error:", pcError);
        pcValue.textContent = "(Error)";
        digestValue.textContent = "(Error)";
        showPcDisplay();
    }
}

function updatePcDisplayForSpecialCases(payload, uuid) {
    if (payload._type === "ob_decrypted") {
        pcValue.textContent = "----------------";
        digestValue.textContent = "--";
        hidePcDisplay();

        return;
    }

    if (payload._type === "needs_uuid" || !uuid) {
        pcValue.textContent = "(UUID required)";
        digestValue.textContent = "(UUID required)";
        hidePcDisplay();
    }
}

// ====================================================================
// INPUT PROCESSING
// ====================================================================

function processFormParams(input, currentUuid) {
    if (!input.includes("payload=") || !input.includes("&")) {
        return { formParams: null, uuid: currentUuid, inputToDecrypt: input };
    }

    const formParams = parseFormParams(input);

    if (!formParams) {
        return { formParams: null, uuid: currentUuid, inputToDecrypt: input };
    }

    console.log("Detected form parameters:", Object.keys(formParams));

    let uuid = currentUuid;

    if (formParams.uuid && !uuid) {
        uuid = formParams.uuid;
        uuidInput.value = uuid;
        console.log("Auto-filled UUID from form params:", uuid);
    }

    if (formParams.payload) {
        inputPayload.value = formParams.payload;
        console.log("Replaced input with payload parameter");
    }

    return {
        formParams,
        uuid,
        inputToDecrypt: formParams.payload || input,
    };
}

function extractObFromJson(input, fallback) {
    try {
        const parsed = JSON.parse(input);

        if (parsed.ob && typeof parsed.ob === "string") {
            return parsed.ob;
        }
    } catch (e) {
        // Not JSON
    }

    return fallback;
}

// ====================================================================
// MAIN PROCESSING
// ====================================================================

async function processPayload() {
    clearTimeout(processingTimeout);
    processingTimeout = setTimeout(async () => {
        try {
            const input = inputPayload.value.trim();
            let uuid = uuidInput.value.trim();

            if (!input) {
                resetUI();

                return;
            }

            setStatus("Processing...", "");
            errorBanner.style.display = "none";

            const {
                formParams,
                uuid: updatedUuid,
                inputToDecrypt: baseInput,
            } = processFormParams(input, uuid);

            uuid = updatedUuid;

            const inputToDecrypt = extractObFromJson(input, baseInput);

            console.log("Starting payload processing ..");
            console.log("Input:", input.substring(0, 100) + " ..");
            console.log("UUID:", uuid || "(none)");

            const decryptedPayload = decryptPayload(inputToDecrypt, uuid, input);

            console.log(
                "Decryption complete. Result type:",
                decryptedPayload._type || decryptedPayload._rawDecrypted
                ? "raw"
                : decryptedPayload._partialDecryption
                ? "partial"
                : "normal",
            );

            outputPayload.value = formatOutput(decryptedPayload);
            await computeAndDisplayPc(decryptedPayload, uuid, formParams);
            updateStatusFromPayload(decryptedPayload);
        } catch (error) {
            showError(error);
        }
    }, 300);
}

// ====================================================================
// CLIPBOARD HELPERS
// ====================================================================

function flashButton(button, text) {
    const span = button.querySelector("span");
    const originalText = span.textContent;

    button.classList.add("success");
    span.textContent = text;
    setTimeout(() => {
        button.classList.remove("success");
        span.textContent = originalText;
    }, 1500);
}

async function handleCopy() {
    try {
        await navigator.clipboard.writeText(outputPayload.value);
        flashButton(copyBtn, "Copied!");
    } catch (err) {
        console.error("Failed to copy:", err);
    }
}

async function handlePaste() {
    try {
        const text = await navigator.clipboard.readText();

        inputPayload.value = text;
        processPayload();
        flashButton(pasteBtn, "Pasted!");
    } catch (err) {
        console.error("Failed to paste:", err);
    }
}

// ====================================================================
// EVENT LISTENERS
// ====================================================================

inputPayload.addEventListener("input", processPayload);
uuidInput.addEventListener("input", processPayload);
copyBtn.addEventListener("click", handleCopy);
pasteBtn.addEventListener("click", handlePaste);

statusText.textContent = "Ready";
