const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json({ limit: '2mb' })); // Adjust if needed

// ===== CONFIGURATION ===== //
const PRIVATE_KEY = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFJDBWBgkqhkiG9w0BBQ0wSTAxBgkqhkiG9w0BBQwwJAQQCqLDKCmUNUGSUANW
QSQ0GQICCAAwDAYIKoZIhvcNAgkFADAUBggqhkiG9w0DBwQIpo0uv/kiA0UEggTI
toUuSqaewXgO6aQCc4rRi65VohF2f84W560VXCklUFqQltghlOEMXmHRPLDvyLha
N/cfQ3IeFFDFnKmRe6rTey14nFOzsz4fw3rVZt+6hO/4i/4l6xRgrBpvFLG1rxCJ
E3npycLx/wW6Z29TjtSyQdgqffr7zq/hFX6UV3vNPAeo+I1eaiEB6GQwG1Vrsv6b
XmzDny4sgaFEWBd0+RJFSYQkJPUDhy9k48ZtYtzrEQsJnMbv39m4I85iYP+PlNFw
9soAJsCiQRZvdoVYuIA79JqtvNpJGN8DAPnZ8FPBCrVjBi+aP8kDOkSdG1olD+gL
hYoFxP60Xy2R8GVdqiXfWWLWtFUZbL1+lQ8Lpu6jGhZMSZPSMmfhoLt4PCMXq9WP
6sgv+iczBggYFnNmq+v204DoVQYxlKktnjPoJCqhVtlH+fw0q7JroBYKld+xGq1i
aedQj6k1r4fyQwOcvKmJhdZRp/sDKq774+wLkYM2/ZLjmSRFInSXRoz9UqLCKAF6
gZpC1QWabfaGxvHcC6LDOfy2PrM+McwRN8eAZ1XykTDAyoXWCSjjzK7Mo6GR25tD
DYYDZ3h7/BTxaoupY5eoYOye81UQagw08835ZpcvHwBB53Z/UDgpLK1DMpNPOZve
mBUsXlnVR7sVrdWcIPPwHqNMznJs1vx2ZE6CSkGVsJC57eS6ulTqVCFCJC7J0gIH
9NOhs2vjiR5bSGNXr2p1lT6Uzo6CvS+ncdozFq0a17eL/OpbhPdk26XEvS4MOztQ
DWW23BTUelqAiR3KORzL7rKWyoi3MwIihyfp9k09PES/yMeFC1e03g7q/pfwfy6Q
nBS8v60XbVwz4ovdVdKriHC/qGVnJ2Q6xb73I14szE0umHRN5Ph5m9UkWEd8HkQC
3z90UYuj2y2aYTcNB/NsKphNl0NdDtYoY1kLhwytiV/CmaMLcLOBYq/aytChWrUH
etdrb8RfprM+de0tktwlrXCLdEmGVICXNGLmeB9RmZGfMYU8Pyvi1RXu/7XNjkpF
+Hy7pWprjVQrou3pAVSdmI9PsTmdSJsjpr6OWOX6MALZznNHzhfLTMziqaetJjgk
r7BcEjDMSUXPtMiTbJQKXNFU1JAlperCGB9ykPBvAJLkg/cdFI1dtyV/QyUSjsIJ
E8lVvaGoPliNqz/XZpT0KC5YtvuALFRHVTMtxza1Eljsq8Izs0ALPVvB5qUCcpZo
cPugOW40RJqaudrKZmyniAGY85vADSwJLuc3YcxPzFp6deqybauzkD9uB6e/cYgv
haJwQvTZIAc9s7uTdbgpEIiGVhmxhvNr6uYf8J81gFfhozjZKgeZhsUfIpN5Di9X
+2Lc4pDOUeCifgzF7fStNWoDkSqxiw8feISV9T/dmx/UF0x62Pk1g8AGU1Jj42Vu
kSedb8kS60iW9h51g77s7R12JJDbkj0sVJAOMg6ZNslk3fygkuLOdjDoG5FGg7sT
nIxfU06tjgV0kYMhdvcbD5EFavWpvF5uN2Nd8RpGBZKQGM/DpnEfjbGmPAPb3ekw
T00Rk+swdJK0046lzTJnbtnUlZ5JYsGIkjKFhYT+azNSykCPefQ1qiDxvqjrNpml
nUEDs4/mXzWqQncLJqhgRWNMNS1ycemi
-----END ENCRYPTED PRIVATE KEY-----
`;

const PORT = process.env.PORT || 3000;

// ===== HELPER: Invert IV bits for response ===== //
function invertBuffer(buf) {
  const inverted = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    inverted[i] = ~buf[i] & 0xff;
  }
  return inverted;
}

// ===== HEALTH CHECK ===== //
app.post('/', (req, res, next) => {
  if (req.body?.action === 'ping') {
    return res.json({
      data: {
        status: "active",
        timestamp: new Date().toISOString(),
        crypto: {
          aesGcm: true,
          rsaOaepSha256: true,
          nodeVersion: process.version
        }
      }
    });
  }
  next();
});

// ===== MAIN FLOW HANDLER ===== //
app.post('/', async (req, res) => {
  try {
    const { encrypted_flow_data, encrypted_aes_key, initial_vector } = req.body;

    if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
      return res.status(400).json({ 
        error: "missing_required_fields",
        details: "encrypted_flow_data, encrypted_aes_key, initial_vector are required"
      });
    }

    // 1. Decrypt AES key (16 bytes)
    const decryptedAESKey = crypto.privateDecrypt({
      key: PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, Buffer.from(encrypted_aes_key, 'base64'));

    if (decryptedAESKey.length !== 16) {
      throw new Error(`AES key length is ${decryptedAESKey.length}, expected 16`);
    }

    // 2. Decode IV
    const iv = Buffer.from(initial_vector, 'base64');
    if (iv.length !== 12) {
      throw new Error(`IV length is ${iv.length}, expected 12 (AES-GCM standard)`);
    }

    // 3. Decode and split encrypted data and auth tag
    const encryptedBuffer = Buffer.from(encrypted_flow_data, 'base64');
    const authTag = encryptedBuffer.slice(encryptedBuffer.length - 16);
    const ciphertext = encryptedBuffer.slice(0, encryptedBuffer.length - 16);

    // 4. Decrypt flow data (AES-128-GCM)
    const decipher = crypto.createDecipheriv('aes-128-gcm', decryptedAESKey, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(ciphertext, undefined, 'utf8');
    decrypted += decipher.final('utf8');

    console.log('🔓 Decrypted Flow Data:', decrypted);

    const requestData = JSON.parse(decrypted);

    // 5. Prepare response payload
    const responsePayload = {
      version: "3.0",
      data: {
        fulfillment_response: {
          messages: [{ text: { body: "Flow processed successfully!" } }]
        }
      }
    };
    const responseString = JSON.stringify(responsePayload);

    // 6. Encrypt response with AES-128-GCM
    const responseIv = invertBuffer(iv);
    const cipher = crypto.createCipheriv('aes-128-gcm', decryptedAESKey, responseIv);
    const encryptedResponseBuffer = Buffer.concat([
      cipher.update(responseString, 'utf8'),
      cipher.final()
    ]);
    const responseAuthTag = cipher.getAuthTag();
    const fullEncryptedResponse = Buffer.concat([encryptedResponseBuffer, responseAuthTag]).toString('base64');

    // 7. Send encrypted response
    res.send(fullEncryptedResponse);

  } catch (error) {
    console.error('❌ Decryption Error:', error.message);
    return res.status(421).json({
      error: "decryption_failed",
      details: error.message,
      nodeVersion: process.version,
      expected: {
        aesKeyLength: "16 bytes",
        ivLength: "12 bytes (GCM)",
        authTagLength: "16 bytes"
      }
    });
  }
});

// ===== SERVER START ===== //
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log('Endpoints: POST / for health check and flow processing');
});
