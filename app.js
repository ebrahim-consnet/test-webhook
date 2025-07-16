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
          aesKeySupport: crypto.getCiphers().includes('aes-256-cbc'),
          rsaSupport: crypto.getCiphers().includes('rsa-oaep')
        }
      }
    });
  }
  next(); // Forward to flow handler
});

// ===== FLOW HANDLER ===== //
app.post('/', async (req, res) => {
  if (!req.body.encrypted_flow_data || !req.body.encrypted_aes_key || !req.body.initial_vector) {
    return res.status(400).json({ error: "Missing required flow data fields" });
  }

  try {
    // 1. Decrypt AES Key (RSA-OAEP)
    const decryptedAESKeyBuffer = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        passphrase: PRIVATE_KEY_PASSPHRASE,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(req.body.encrypted_aes_key, 'base64')
    );

    // 2. Validate and prepare AES-256 key
    const aesKey = Buffer.alloc(32); // Ensure exactly 32 bytes
    decryptedAESKeyBuffer.copy(aesKey, 0, 0, 32);
    
    console.log('🔑 Derived AES Key:', aesKey.toString('base64'));
    if (aesKey.length !== 32) throw new Error(`Invalid AES key length: ${aesKey.length} bytes`);

    // 3. Prepare IV
    const iv = Buffer.from(req.body.initial_vector, 'base64');
    if (iv.length !== 16) throw new Error(`Invalid IV length: ${iv.length} bytes`);

    // 4. Decrypt Flow Data
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    let decrypted = decipher.update(req.body.encrypted_flow_data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    console.log('🔓 Decrypted Flow Data:', decrypted);

    // 5. Prepare Response
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
    console.error('❌ Critical Error:', {
      error: error.message,
      stack: error.stack,
      receivedData: {
        encrypted_aes_key: req.body.encrypted_aes_key?.length,
        initial_vector: req.body.initial_vector,
        flow_data: req.body.encrypted_flow_data?.length
      }
    });

    return res.status(421).json({
      error: "crypto_processing_error",
      details: error.message,
      expected: {
        aesKeyLength: "32 bytes",
        ivLength: "16 bytes",
        keyFormat: "PKCS#8 encrypted private key"
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
  console.log('- AES-256-CBC:', crypto.getCiphers().includes('aes-256-cbc'));
  console.log('- RSA-OAEP:', crypto.getCiphers().includes('rsa-oaep'));
});
