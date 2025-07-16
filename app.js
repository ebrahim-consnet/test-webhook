const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

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
-----END ENCRYPTED PRIVATE KEY-----`;
const PRIVATE_KEY_PASSPHRASE = "1234";

// ===== CRYPTO COMPATIBILITY ===== //
const RSA_OAEP_SUPPORTED = crypto.getCiphers().includes('rsa-oaep');
console.log(`🔐 Crypto Support - RSA-OAEP: ${RSA_OAEP_SUPPORTED}`);

// ===== MIDDLEWARE ===== //
app.use((req, res, next) => {
  console.log(`📥 ${req.method} ${req.path}`);
  next();
});

// ===== HEALTH CHECK ===== //
app.post('/', (req, res) => {
  if (req.body?.action === 'ping') {
    console.log('🩺 Health check received');
    return res.json({
      data: {
        status: "active",
        timestamp: new Date().toISOString(),
        crypto: {
          aes256: true,
          rsaOaep: RSA_OAEP_SUPPORTED,
          nodeVersion: process.version,
          usingFallback: !RSA_OAEP_SUPPORTED
        }
      }
    });
  }
  next(); // Forward to flow handler
});

// ===== FLOW HANDLER ===== //
app.post('/', async (req, res) => {
  if (!req.body.encrypted_flow_data || !req.body.encrypted_aes_key || !req.body.initial_vector) {
    return res.status(400).json({ 
      error: "missing_required_fields",
      details: "Request must contain encrypted_flow_data, encrypted_aes_key, and initial_vector"
    });
  }

  try {
    // 1. Decrypt AES Key
    const decryptedAESKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        passphrase: PRIVATE_KEY_PASSPHRASE,
        padding: RSA_OAEP_SUPPORTED 
          ? crypto.constants.RSA_PKCS1_OAEP_PADDING
          : crypto.constants.RSA_PKCS1_PADDING
      },
      Buffer.from(req.body.encrypted_aes_key, 'base64')
    );

    // 2. Prepare AES-256 Key (exactly 32 bytes)
    const aesKey = Buffer.alloc(32);
    decryptedAESKey.copy(aesKey, 0, 0, 32);
    
    // 3. Prepare IV (exactly 16 bytes)
    const iv = Buffer.from(req.body.initial_vector, 'base64');
    if (iv.length !== 16) {
      throw new Error(`Invalid IV length: ${iv.length} bytes (needs 16)`);
    }

    // 4. Decrypt Flow Data
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    let decrypted = decipher.update(req.body.encrypted_flow_data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    console.log('🔓 Decrypted Flow Data:', decrypted);

    // 5. Prepare Meta-compliant Response
    const response = {
      version: "3.0",
      data: {
        fulfillment_response: {
          messages: [{
            text: { body: "Flow processed successfully!" }
          }]
        }
      }
    };

    // 6. Encrypt Response
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encryptedResponse = cipher.update(JSON.stringify(response), 'utf8', 'base64');
    encryptedResponse += cipher.final('base64');

    return res.send(encryptedResponse);

  } catch (error) {
    console.error('❌ Decryption Error:', {
      error: error.message,
      stack: error.stack,
      cryptoSupport: {
        rsaOaep: RSA_OAEP_SUPPORTED,
        nodeVersion: process.version
      }
    });

    return res.status(421).json({
      error: "decryption_failed",
      details: error.message,
      cryptoInfo: {
        paddingUsed: RSA_OAEP_SUPPORTED ? "OAEP" : "PKCS1",
        nodeVersion: process.version,
        requiredKeyLengths: {
          aesKey: "32 bytes",
          iv: "16 bytes"
        }
      }
    });
  }
});

// ===== SERVER ===== //
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log('Endpoints:');
  console.log(`POST / - Health checks and flow processing`);
  console.log('\n🔐 Crypto Support:');
  console.log('- Node Version:', process.version);
  console.log('- RSA-OAEP:', RSA_OAEP_SUPPORTED);
  console.log('- AES-256-CBC:', crypto.getCiphers().includes('aes-256-cbc'));
});
