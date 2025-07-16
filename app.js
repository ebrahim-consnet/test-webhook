const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// ✅ Hardcoded values
const PORT = 3000;
const VERIFY_TOKEN = 'token';
const PRIVATE_KEY = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
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
const PRIVATE_KEY_PASSPHRASE = '1234';

// ✅ Webhook verification
app.get('/', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('✅ WEBHOOK VERIFIED');
    return res.status(200).send(challenge);
  } else {
    return res.sendStatus(403);
  }
});

// ✅ Handle POST requests (Health check + Flow data)
app.post('/', async (req, res) => {
  const body = req.body;
  console.log('📥 Incoming Webhook:', JSON.stringify(body, null, 2));

  // Health check
  if (body.action === 'ping') {
    console.log('✅ Health check received');
    return res.json({ data: { status: 'active' } });
  }

  // Handle flow encryption
  if (body.encrypted_flow_data && body.encrypted_aes_key && body.initial_vector) {
    try {
      const decryptedAESKey = crypto.privateDecrypt(
        {
          key: PRIVATE_KEY,
          passphrase: PRIVATE_KEY_PASSPHRASE,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        Buffer.from(body.encrypted_aes_key, 'base64')
      );

      const iv = Buffer.from(body.initial_vector, 'base64');
      const encryptedFlowData = Buffer.from(body.encrypted_flow_data, 'base64');

      const decipher = crypto.createDecipheriv('aes-128-cbc', decryptedAESKey, iv);
      let decryptedData = decipher.update(encryptedFlowData, null, 'utf8');
      decryptedData += decipher.final('utf8');

      console.log('✅ Decrypted Flow Data:', decryptedData);

      const responseObject = {
        message: 'Flow processed successfully',
        received: JSON.parse(decryptedData),
      };

      const responseString = JSON.stringify(responseObject);
      const cipher = crypto.createCipheriv('aes-128-cbc', decryptedAESKey, iv);
      let encryptedResponse = cipher.update(responseString, 'utf8', 'base64');
      encryptedResponse += cipher.final('base64');

      return res.status(200).send(encryptedResponse);
    } catch (error) {
      console.error('❌ Decryption Error:', error.message);
      return res.status(421).send('Unable to decrypt request');
    }
  }

  res.sendStatus(200);
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
