// Import required modules
const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// Environment variables
const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const PRIVATE_KEY = Buffer.from(process.env.PRIVATE_KEY_BASE64, 'base64').toString('utf8');

// --- 1. VERIFY WEBHOOK (GET) ---
app.get('/', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('✅ WEBHOOK VERIFIED');
    res.status(200).send(challenge);
  } else {
    res.status(403).send('Forbidden');
  }
});

// --- 2. HANDLE POST REQUESTS (Webhook + Health Check + Flow Encryption) ---
app.post('/', async (req, res) => {
  const body = req.body;
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\n📥 Webhook received at ${timestamp}\n`, JSON.stringify(body, null, 2));

  // --- Health Check ---
  if (body.action === 'ping') {
    console.log('✅ Health Check Received');
    return res.json({ data: { status: 'active' } });
  }

  // --- WhatsApp Flow Payload ---
  if (body.encrypted_flow_data && body.encrypted_aes_key && body.initial_vector) {
    try {
      // Step 1: Decrypt AES key using RSA Private Key
      const decryptedAESKey = crypto.privateDecrypt(
        {
          key: PRIVATE_KEY,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        },
        Buffer.from(body.encrypted_aes_key, 'base64')
      );

      // Step 2: Decrypt Flow Data using AES key and IV
      const iv = Buffer.from(body.initial_vector, 'base64');
      const encryptedFlowData = Buffer.from(body.encrypted_flow_data, 'base64');

      const decipher = crypto.createDecipheriv('aes-128-cbc', decryptedAESKey, iv);
      let decryptedData = decipher.update(encryptedFlowData, null, 'utf8');
      decryptedData += decipher.final('utf8');

      console.log('✅ Decrypted Flow Data:', decryptedData);

      // Here you can process `decryptedData` and create your response
      const responseObject = {
        message: 'Flow processed successfully',
        received: JSON.parse(decryptedData),
      };

      // Step 3: Encrypt response using AES key
      const responseString = JSON.stringify(responseObject);
      const cipher = crypto.createCipheriv('aes-128-cbc', decryptedAESKey, iv);
      let encryptedResponse = cipher.update(responseString, 'utf8', 'base64');
      encryptedResponse += cipher.final('base64');

      return res.status(200).send(encryptedResponse);
    } catch (error) {
      console.error('❌ Decryption Error:', error);
      return res.status(421).send('Unable to decrypt request');
    }
  }

  // If none of the above, acknowledge with 200 OK
  res.sendStatus(200);
});

// Start the server
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
