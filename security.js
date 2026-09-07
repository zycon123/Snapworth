import sharp from 'sharp';

export class PublicError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export function databaseOptions(env) {
  if (!env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  const url = new URL(env.DATABASE_URL);
  // URL SSL flags can override pg's ssl object. Keep one verified TLS policy.
  for (const name of ['sslmode', 'sslcert', 'sslkey', 'sslrootcert', 'uselibpqcompat']) url.searchParams.delete(name);
  return { connectionString: url.toString(), ssl: env.NODE_ENV === 'production'
    ? { rejectUnauthorized: true, ...(env.DATABASE_CA_CERT ? { ca: env.DATABASE_CA_CERT.replace(/\\n/g, '\n') } : {}) } : false,
    max: 10, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000, statement_timeout: 10000, query_timeout: 12000 };
}
export function validateEnvironment(env) {
  if (env.NODE_ENV === 'production' && (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32 || /change|development|example/i.test(env.SESSION_SECRET))) {
    throw new Error('Set a random SESSION_SECRET of at least 32 characters before starting production.');
  }
}
export function validatePublicSignup(env) {
  if (env.NODE_ENV === 'production' && env.PUBLIC_SIGNUP_ENABLED === 'true' &&
      (!env.SITE_OPERATOR?.trim() || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(env.SUPPORT_EMAIL || '') || env.POLICIES_REVIEWED !== 'true')) {
    throw new Error('Public signup requires SITE_OPERATOR, SUPPORT_EMAIL and reviewed policies.');
  }
}
export const MAX_PRICE = 10000000;
export const currencies = new Set(['USD', 'GBP', 'EUR', 'NOK']);
export function text(value, max, required = false) {
  if (value == null && !required) return '';
  if (typeof value !== 'string' || value.length > max || (required && !value.trim())) throw new PublicError(400, 'Invalid text field.');
  return value.trim();
}
export function amount(value, nullable = true) {
  if (value === null || value === undefined || value === '') {
    if (nullable) return null;
    throw new PublicError(400, 'A positive price is required.');
  }
  if (!['number','string'].includes(typeof value) || !Number.isFinite(Number(value)) || Number(value) <= 0 || Number(value) > MAX_PRICE) throw new PublicError(400, 'Price must be positive and within the supported range.');
  return Number(value);
}
export function itemInput(x) {
  if (!x || typeof x !== 'object' || Array.isArray(x)) throw new PublicError(400, 'Invalid item.');
  const currency = text(x.currency, 3, true);
  if (!currencies.has(currency)) throw new PublicError(400, 'Unsupported currency.');
  const value = amount(x.value), low = amount(x.low), high = amount(x.high);
  if ((low !== null && high !== null && low > high) || (value === null && (low !== null || high !== null))) throw new PublicError(400, 'Invalid price range.');
  return { name: text(x.name, 240, true), value, low, high, currency,
    condition: text(x.condition, 80), category: text(x.category, 80), notes: text(x.notes, 2000) };
}
export async function normalizeImage(buffer, declaredType, maxBytes = 8 * 1024 * 1024) {
  const formats = { 'image/jpeg': 'jpeg', 'image/png': 'png', 'image/webp': 'webp' };
  if (!formats[declaredType]) throw new PublicError(415, 'Use a JPEG, PNG or WebP image.');
  if (!Buffer.isBuffer(buffer) || !buffer.length) throw new PublicError(400, 'An image is required.');
  if (buffer.length > maxBytes) throw new PublicError(413, 'Image is too large.');
  try {
    const image = sharp(buffer, { limitInputPixels: 20000000, failOn: 'warning', animated: false });
    const meta = await image.metadata();
    if (meta.format !== formats[declaredType] || (meta.pages || 1) > 1 || !meta.width || !meta.height || meta.width * meta.height > 20000000) throw new Error('Invalid image');
    // Decode fully, orient, resize both dimensions and strip metadata before use/storage.
    return await image.rotate().resize({ width: 1280, height: 1280, fit: 'inside', withoutEnlargement: true }).jpeg({ quality: 80 }).toBuffer();
  } catch { throw new PublicError(400, 'Image could not be read. Use a valid image under 20 megapixels.'); }
}
export async function storedImage(value) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string' || value.length > 1500000) throw new PublicError(413, 'Saved image is too large.');
  const match = value.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/]+={0,2})$/);
  if (!match || match[2].length % 4 !== 0) throw new PublicError(400, 'Invalid image data.');
  const bytes = Buffer.from(match[2], 'base64');
  if (bytes.toString('base64') !== match[2]) throw new PublicError(400, 'Invalid image data.');
  return 'data:image/jpeg;base64,' + (await normalizeImage(bytes, match[1], 1125000)).toString('base64');
}
const categories = new Set(['Electronics','Tools','Games & Consoles','Collectibles','Furniture','Car Parts','Clothing','Watches','Toys','Home & Appliances','Other']);
export function identification(payload) {
  try {
    if (!Array.isArray(payload.output) || (payload.status && payload.status !== 'completed')) throw new Error();
    const raw = payload.output.flatMap(x => Array.isArray(x.content) ? x.content : []).filter(x => x.type === 'output_text' || !x.type).map(x => typeof x.text === 'string' ? x.text : '').join('').trim();
    const clean = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
    const d = JSON.parse(clean);
    if (!d || Array.isArray(d) || !categories.has(d.category) || typeof d.confidence !== 'number' || !Number.isFinite(d.confidence) || d.confidence < 0 || d.confidence > 1) throw new Error();
    const optional = (v, n) => v === null || v === 'null' ? null : text(v, n) || null;
    return { item_name: text(d.item_name, 240, true), brand: optional(d.brand,120), model: optional(d.model,120), category:d.category,
      confidence:d.confidence, notes: text(d.notes,1000), search_query:text(d.search_query || d.item_name,240,true), search_query_no:text(d.search_query_no || d.search_query || d.item_name,240,true),
      needs_more_photos:d.needs_more_photos === true, photo_request:optional(d.photo_request,500) };
  } catch { throw new PublicError(502, 'The image could not be identified reliably. Try a clearer photo.'); }
}
export async function fetchJson(fetcher, url, options = {}, timeout = 20000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetcher(url, { ...options, signal: controller.signal });
    if (!response.ok) {
      await response.body?.cancel();
      const error = new PublicError(response.status === 429 ? 503 : 502, 'External service is temporarily unavailable. Please try again later.');
      error.upstreamStatus = response.status;
      throw error;
    }
    const reader = response.body.getReader();
    let length=0; const chunks=[];
    try {
      while (true) { const { done, value } = await reader.read(); if (done) break; length += value.length; if (length > 2000000) throw new PublicError(502, 'External response was too large.'); chunks.push(Buffer.from(value)); }
    } finally { await reader.cancel().catch(()=>{}); }
    try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { throw new PublicError(502, 'External service returned an invalid response.'); }
  } catch (e) {
    if (controller.signal.aborted) throw new PublicError(504, 'The request took too long. Please try again.');
    if (e instanceof PublicError) throw e;
    throw new PublicError(502, 'External service is temporarily unavailable. Please try again later.');
  } finally { clearTimeout(timer); }
}
