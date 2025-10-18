# PerimeterX Decoder

Decrypt and verify PerimeterX request/response payloads.

**Live Demo:** https://boiln.github.io/perimeterx-decoder/

https://github.com/user-attachments/assets/229f2d5e-d281-460b-b1c4-1b0896badaa3

## Features

-   Request payload decryption (UUID-based XOR encryption)
-   Response payload decryption (OB field XOR)
-   PC signature verification
-   Client-side processing (no data leaves your browser)

## Usage

1. Paste encrypted payload
2. Enter UUID (for request payloads)
3. View decrypted JSON and signature verification

## API

```javascript
import { decrypt } from "./decrypt.js";
import { decryptOb } from "./decryptOb.js";

// Request payload
const result = decrypt(encryptedPayload, uuid);

// Response payload
const { decrypted, key } = decryptOb(obField);
```

## License

MIT

---

**Disclaimer:** For educational and security research purposes only.
