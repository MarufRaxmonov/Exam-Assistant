const crypto = require('node:crypto');

// Vercel serverless function: multipart/form-data ni o‘zimiz o‘qiymiz,
// shuning uchun qo‘shimcha npm paketi talab qilinmaydi.

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;

    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > 10 * 1024 * 1024) {
        reject(new Error('Natija rasmi hajmi 10 MB dan oshmasligi kerak.'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseContentDisposition(value) {
  const result = {};
  value.split(';').slice(1).forEach((part) => {
    const separator = part.indexOf('=');
    if (separator === -1) return;
    const key = part.slice(0, separator).trim();
    const rawValue = part.slice(separator + 1).trim();
    result[key] = rawValue.replace(/^"(.*)"$/, '$1');
  });
  return result;
}

function parseMultipart(body, contentType) {
  const boundaryMatch = String(contentType || '').match(/boundary="?([^";]+)"?/i);
  if (!boundaryMatch) {
    throw new Error('multipart/form-data boundary topilmadi.');
  }

  const boundary = Buffer.from(`--${boundaryMatch[1]}`);
  const separator = Buffer.from('\r\n\r\n');
  const fields = {};
  let cursor = 0;

  while (cursor < body.length) {
    let partStart = body.indexOf(boundary, cursor);
    if (partStart === -1) break;

    partStart += boundary.length;
    if (body.slice(partStart, partStart + 2).toString() === '--') break;
    if (body.slice(partStart, partStart + 2).toString() === '\r\n') partStart += 2;

    const headerEnd = body.indexOf(separator, partStart);
    if (headerEnd === -1) break;

    const headers = body.slice(partStart, headerEnd).toString('utf8');
    const dispositionMatch = headers.match(/content-disposition:\s*([^\r\n]+)/i);
    if (!dispositionMatch) {
      cursor = headerEnd + separator.length;
      continue;
    }

    const disposition = parseContentDisposition(dispositionMatch[1]);
    const name = disposition.name;
    if (!name) {
      cursor = headerEnd + separator.length;
      continue;
    }

    const contentStart = headerEnd + separator.length;
    const nextBoundary = body.indexOf(boundary, contentStart);
    if (nextBoundary === -1) break;

    const contentEnd = Math.max(contentStart, nextBoundary - 2);
    const content = body.slice(contentStart, contentEnd);
    const contentTypeMatch = headers.match(/content-type:\s*([^\r\n]+)/i);

    fields[name] = {
      value: disposition.filename ? null : content.toString('utf8'),
      buffer: disposition.filename ? content : null,
      filename: disposition.filename || '',
      contentType: contentTypeMatch ? contentTypeMatch[1].trim() : ''
    };

    cursor = nextBoundary;
  }

  return fields;
}

function safeEqualHex(left, right) {
  if (!/^[a-f0-9]{64}$/i.test(left) || !/^[a-f0-9]{64}$/i.test(right)) {
    return false;
  }
  return crypto.timingSafeEqual(
    Buffer.from(left, 'hex'),
    Buffer.from(right, 'hex')
  );
}

function verifyTelegramInitData(initData, botToken) {
  const params = new URLSearchParams(String(initData || ''));
  const receivedHash = params.get('hash');
  if (!receivedHash) throw new Error('Telegram initData hash topilmadi.');

  const dataCheckString = [...params.entries()]
    .filter(([key]) => key !== 'hash')
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');

  const secretKey = crypto
    .createHmac('sha256', 'WebAppData')
    .update(botToken)
    .digest();
  const calculatedHash = crypto
    .createHmac('sha256', secretKey)
    .update(dataCheckString)
    .digest('hex');

  if (!safeEqualHex(receivedHash, calculatedHash)) {
    throw new Error('Telegram foydalanuvchisi tasdiqlanmadi.');
  }

  const authDate = Number(params.get('auth_date') || 0);
  if (!authDate || Math.floor(Date.now() / 1000) - authDate > 24 * 60 * 60) {
    throw new Error('Telegram sessiyasi eskirgan. Ilovani qayta oching.');
  }

  let user;
  try {
    user = JSON.parse(params.get('user') || '{}');
  } catch {
    throw new Error('Telegram foydalanuvchisi ma’lumotlari noto‘g‘ri.');
  }

  if (!user.id) throw new Error('Telegram user ID topilmadi.');
  return user;
}

function sendJson(res, status, payload) {
  res.status(status).json(payload);
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    sendJson(res, 405, { ok: false, error: 'Faqat POST so‘rovi qabul qilinadi.' });
    return;
  }

  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  if (!botToken) {
    sendJson(res, 500, {
      ok: false,
      error: 'TELEGRAM_BOT_TOKEN Vercel Environment Variables’da sozlanmagan.'
    });
    return;
  }

  try {
    const body = await readRequestBody(req);
    const fields = parseMultipart(body, req.headers['content-type']);
    const initData = fields.init_data?.value;
    const requestedChatId = String(fields.chat_id?.value || '');
    const photo = fields.photo;

    if (!photo?.buffer?.length) {
      sendJson(res, 400, { ok: false, error: 'Natija rasmi yuborilmadi.' });
      return;
    }

    const telegramUser = verifyTelegramInitData(initData, botToken);
    const verifiedChatId = String(telegramUser.id);

    // Foydalanuvchi boshqa chat_id berib botdan begona chatlarga yubora
    // olmasligi uchun faqat initData ichidagi o‘z ID’siga yuboramiz.
    if (!requestedChatId || requestedChatId !== verifiedChatId) {
      sendJson(res, 403, {
        ok: false,
        error: 'Natija faqat ilovani ochgan foydalanuvchining Telegram chatiga yuboriladi.'
      });
      return;
    }

    const telegramForm = new FormData();
    telegramForm.append('chat_id', verifiedChatId);
    telegramForm.append(
      'photo',
      new Blob([photo.buffer], { type: photo.contentType || 'image/png' }),
      photo.filename || `exam-assistant-natija-${Date.now()}.png`
    );
    telegramForm.append(
      'caption',
      fields.caption?.value || 'Sizning real imtihon natijangiz!'
    );

    const telegramResponse = await fetch(
      `https://api.telegram.org/bot${encodeURIComponent(botToken)}/sendPhoto`,
      { method: 'POST', body: telegramForm }
    );
    const telegramResult = await telegramResponse.json().catch(() => ({}));

    if (!telegramResponse.ok || !telegramResult.ok) {
      const description = telegramResult.description || 'Telegram rasmni qabul qilmadi.';
      sendJson(res, 502, { ok: false, error: description });
      return;
    }

    sendJson(res, 200, {
      ok: true,
      message_id: telegramResult.result?.message_id || null
    });
  } catch (error) {
    sendJson(res, 400, {
      ok: false,
      error: error?.message || 'Natijani Telegramga yuborishda xatolik yuz berdi.'
    });
  }
};

module.exports.config = {
  api: {
    bodyParser: false,
    sizeLimit: '10mb'
  }
};
