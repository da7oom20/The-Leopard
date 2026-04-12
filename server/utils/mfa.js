const crypto = require('crypto');
const QRCode = require('qrcode');

const MFA = {
  base32Encode: (buffer) => {
    const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (let i = 0; i < buffer.length; i++) {
      bits += buffer[i].toString(2).padStart(8, '0');
    }
    while (bits.length % 5 !== 0) {
      bits += '0';
    }
    let result = '';
    for (let i = 0; i < bits.length; i += 5) {
      const chunk = bits.substr(i, 5);
      result += base32chars[parseInt(chunk, 2)];
    }
    return result;
  },

  base32Decode: (secret) => {
    const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const char of secret.toUpperCase()) {
      const val = base32chars.indexOf(char);
      if (val === -1) continue;
      bits += val.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.substr(i, 8), 2));
    }
    return Buffer.from(bytes);
  },

  generateSecret: () => {
    const buffer = crypto.randomBytes(20);
    return MFA.base32Encode(buffer);
  },

  generateTOTP: (secret, window = 0) => {
    const time = Math.floor(Date.now() / 1000 / 30) + window;
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeBigInt64BE(BigInt(time));

    const keyBuffer = MFA.base32Decode(secret);

    const hmac = crypto.createHmac('sha1', keyBuffer);
    hmac.update(timeBuffer);
    const hash = hmac.digest();

    const offset = hash[hash.length - 1] & 0xf;
    const code = ((hash[offset] & 0x7f) << 24 |
                  (hash[offset + 1] & 0xff) << 16 |
                  (hash[offset + 2] & 0xff) << 8 |
                  (hash[offset + 3] & 0xff)) % 1000000;

    return code.toString().padStart(6, '0');
  },

  verifyTOTP: (secret, token) => {
    if (typeof token !== 'string' || token.length !== 6) return false;
    let valid = false;
    for (let window = -2; window <= 2; window++) {
      const generated = MFA.generateTOTP(secret, window);
      if (generated.length === token.length &&
          crypto.timingSafeEqual(Buffer.from(generated), Buffer.from(token))) {
        valid = true;
      }
    }
    return valid;
  },

  generateBackupCodes: (count = 8) => {
    const codes = [];
    for (let i = 0; i < count; i++) {
      codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }
    return codes;
  },

  generateQRCodeDataURL: async (secret, username, issuer = 'The Leopard') => {
    const otpauth = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(username)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return QRCode.toDataURL(otpauth);
  }
};

module.exports = MFA;
