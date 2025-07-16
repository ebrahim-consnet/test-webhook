const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

// ===== CONFIGURATION ===== //
const PRIVATE_KEY = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFJDBWBgkqhkiG9w0BBQ0wSTAxBgkqhkiG9w0BBQwwJAQQCqLDKCmUNUGSUANW
... [your full key here] ...
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
