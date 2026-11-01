/* 알록다록 리뷰 게시판 서버 (Cloudflare Worker)
   - 방문자는 닉네임 + 비밀번호로 리뷰를 쓰고, 같은 비밀번호로 고치거나 지운다.
   - 관리자 비밀번호(ADMIN_PASSWORD)로는 모든 리뷰를 지울 수 있고 '관리자' 닉네임을 쓸 수 있다.
   - 리뷰는 비공개 GitHub 저장소(DATA_REPO)의 board.json 한 파일에 저장한다. 토큰은 Worker 비밀값에만 있다.
   - 같은 IP는 짧은 시간에 여러 번 쓰지 못한다(RATE KV).

   비밀값(wrangler secret put): GITHUB_TOKEN, ADMIN_PASSWORD, PEPPER
   변수(wrangler.toml): DATA_REPO, DATA_PATH, ALLOWED_ORIGINS
*/

const MAX_TEXT = 500, MAX_NAME = 20, DEFAULT_NAME = '차갤러', ADMIN_NAME = '관리자';
const RATE_GAP = 3 * 1000;             // 글과 글 사이 최소 간격 (실수로 두 번 누르는 것 방지)
const RATE_WINDOW = 60 * 1000;         // 새 글: 1분 동안
const RATE_MAX = 5;                    // 최대 5개
const RATE_WINDOW_EDIT = 10 * 60 * 1000; // 수정·삭제 시도: 10분 동안 (비밀번호 맞히기 방지)
const RATE_MAX_EDIT = 15;                // 최대 15번
const PBKDF2_ITER = 5000;              // 무료 요금제 CPU 한도(10ms) 안에서 돌도록 낮게, 대신 PEPPER로 보완

export default {
  async fetch(req, env, ctx) {
    const origin = req.headers.get('Origin') || '';
    const allowed = (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
    const cors = {
      'Access-Control-Allow-Origin': allowed.includes(origin) ? origin : allowed[0] || '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
      Vary: 'Origin',
    };
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8' } });
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    const url = new URL(req.url);
    try {
      if (req.method === 'GET' && url.pathname === '/reviews') {
        const { board } = await readBoard(env);
        return json({ reviews: board.reviews.map(publicView) });
      }
      if (req.method !== 'POST') return json({ error: '지원하지 않는 요청입니다.' }, 404);
      if (origin && allowed.length && !allowed.includes(origin)) return json({ error: '허용되지 않은 사이트입니다.' }, 403);

      const body = await req.json().catch(() => null);
      if (!body || typeof body !== 'object') return json({ error: '요청 형식이 잘못되었습니다.' }, 400);
      const ip = req.headers.get('CF-Connecting-IP') || 'unknown';
      const isAdmin = !!env.ADMIN_PASSWORD && typeof body.password === 'string' && timingSafeEq(body.password, env.ADMIN_PASSWORD);

      if (url.pathname === '/reviews') return json(await create(env, body, ip, isAdmin));
      if (url.pathname === '/admin/check') { // 관리 페이지 로그인: 틀린 시도는 수정·삭제와 같은 횟수 제한을 받음
        if (!isAdmin) { await rateLimit(env, ip, false, 'edit'); throw new UserError('관리자 비밀번호가 맞지 않습니다.', 403); }
        return json({ ok: true });
      }
      const m = url.pathname.match(/^\/reviews\/([a-z0-9]{6,32})\/(edit|delete)$/);
      if (m) return json(await (m[2] === 'edit' ? edit : remove)(env, m[1], body, ip, isAdmin));
      return json({ error: '지원하지 않는 요청입니다.' }, 404);
    } catch (e) {
      if (e instanceof UserError) return json({ error: e.message }, e.status);
      console.error(e);
      return json({ error: '서버에서 문제가 생겼습니다. 잠시 뒤 다시 시도하십시오.' }, 500);
    }
  },
};

class UserError extends Error { constructor(msg, status = 400) { super(msg); this.status = status; } }

const publicView = (r) => ({ id: r.id, name: r.name, teaId: r.teaId, v: r.v, text: r.text, t: r.t, edited: r.edited || 0, admin: !!r.admin });

function cleanName(n, isAdmin) {
  n = String(n == null ? '' : n).replace(/\s+/g, ' ').trim().slice(0, MAX_NAME) || DEFAULT_NAME;
  if (n.replace(/\s/g, '') === ADMIN_NAME && !isAdmin) throw new UserError("'관리자'는 쓸 수 없는 닉네임입니다.");
  return n;
}
function cleanRating(v) {
  if (v == null || v === '' || v === 0) return 0;
  v = +v;
  if (!(v >= 0.5 && v <= 5 && Math.round(v * 2) === v * 2)) throw new UserError('별점은 0.5~5점 사이에서 0.5점 단위로 고르십시오.');
  return v;
}
function cleanText(s) { return String(s == null ? '' : s).replace(/\r\n?/g, '\n').trim().slice(0, MAX_TEXT); }
function cleanPassword(p) {
  if (typeof p !== 'string' || p.length < 4 || p.length > 64) throw new UserError('비밀번호는 4~64자로 입력하십시오.');
  return p;
}

async function create(env, b, ip, isAdmin) {
  const teaId = String(b.teaId || '');
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(teaId)) throw new UserError('차 정보가 잘못되었습니다.');
  const password = cleanPassword(b.password);
  const name = cleanName(b.name, isAdmin), v = cleanRating(b.v), text = cleanText(b.text);
  if (!v && !text) throw new UserError('별점이나 내용 중 하나는 남겨 주십시오.');
  await rateLimit(env, ip, isAdmin);
  const salt = randomId(16);
  const r = { id: randomId(12), name, teaId, v, text, t: Date.now(), salt, pw: await hashPw(password, salt, env), ...(isAdmin && name === ADMIN_NAME ? { admin: true } : {}) };
  await updateBoard(env, (board) => { board.reviews.push(r); }, '리뷰 추가');
  return { ok: true, review: publicView(r) };
}

async function edit(env, id, b, ip, isAdmin) {
  const password = cleanPassword(b.password);
  const v = cleanRating(b.v), text = cleanText(b.text);
  if (!v && !text) throw new UserError('별점이나 내용 중 하나는 남겨 주십시오.');
  await rateLimit(env, ip, isAdmin, 'edit');
  let out;
  await updateBoard(env, async (board) => {
    const r = board.reviews.find((x) => x.id === id);
    if (!r) throw new UserError('이미 지워진 리뷰입니다.', 404);
    if (!(await checkPw(r, password, env))) throw new UserError('비밀번호가 맞지 않습니다.', 403); // 수정은 본인만
    r.v = v; r.text = text; r.edited = Date.now(); out = publicView(r);
  }, '리뷰 수정');
  return { ok: true, review: out };
}

async function remove(env, id, b, ip, isAdmin) {
  const password = cleanPassword(b.password);
  await rateLimit(env, ip, isAdmin, 'edit');
  await updateBoard(env, async (board) => {
    const i = board.reviews.findIndex((x) => x.id === id);
    if (i < 0) throw new UserError('이미 지워진 리뷰입니다.', 404);
    if (!isAdmin && !(await checkPw(board.reviews[i], password, env))) throw new UserError('비밀번호가 맞지 않습니다.', 403);
    board.reviews.splice(i, 1);
  }, isAdmin ? '관리자 삭제' : '리뷰 삭제');
  return { ok: true };
}

/* ── 도배 방지: IP를 해시한 키로 최근 기록 시각을 KV에 보관 ── */
async function rateLimit(env, ip, isAdmin, kind = 'post') {
  if (isAdmin || !env.RATE) return;
  const key = (kind === 'post' ? 'rl:' : 'rle:') + (await sha256Hex(ip + '|' + (env.PEPPER || ''))).slice(0, 32);
  const now = Date.now();
  let times = [];
  const win = kind === 'post' ? RATE_WINDOW : RATE_WINDOW_EDIT;
  try { times = JSON.parse((await env.RATE.get(key)) || '[]').filter((t) => now - t < win); } catch (e) {}
  const last = times.length ? Math.max(...times) : 0;
  if (kind === 'post' && now - last < RATE_GAP) throw new UserError(`너무 빨리 쓰고 있습니다. ${Math.ceil((RATE_GAP - (now - last)) / 1000)}초 뒤에 다시 시도하십시오.`, 429);
  if (times.length >= (kind === 'post' ? RATE_MAX : RATE_MAX_EDIT)) throw new UserError(kind === 'post' ? '1분에 5개까지만 쓸 수 있습니다. 잠시 뒤에 다시 시도하십시오.' : '수정·삭제를 너무 많이 시도했습니다. 10분쯤 뒤에 다시 시도하십시오.', 429);
  times.push(now);
  await env.RATE.put(key, JSON.stringify(times), { expirationTtl: Math.ceil(win / 1000) + 60 });
}

/* ── GitHub 저장소의 board.json 읽기/쓰기 ── */
function ghHeaders(env) {
  return { Authorization: 'Bearer ' + env.GITHUB_TOKEN, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'darok-board' };
}
const contentsUrl = (env) => `https://api.github.com/repos/${env.DATA_REPO}/contents/${env.DATA_PATH || 'board.json'}`;

async function readBoard(env) {
  const r = await fetch(contentsUrl(env) + '?ref=main', { headers: ghHeaders(env) });
  if (r.status === 404) return { board: { app: 'darok', kind: 'board', reviews: [] }, sha: undefined };
  if (!r.ok) throw new Error('GitHub read ' + r.status);
  const j = await r.json();
  let board;
  if (j.content) board = JSON.parse(b64decode(j.content));
  else { // 1MB가 넘으면 content가 비어 오므로 raw로 다시 받음
    const raw = await fetch(contentsUrl(env) + '?ref=main', { headers: { ...ghHeaders(env), Accept: 'application/vnd.github.raw+json' } });
    board = await raw.json();
  }
  if (!board || !Array.isArray(board.reviews)) board = { app: 'darok', kind: 'board', reviews: [] };
  return { board, sha: j.sha };
}

async function updateBoard(env, fn, message) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const { board, sha } = await readBoard(env);
    await fn(board);
    board.updatedAt = new Date().toISOString();
    const r = await fetch(contentsUrl(env), {
      method: 'PUT', headers: ghHeaders(env),
      body: JSON.stringify({ message, content: b64encode(JSON.stringify(board, null, 1)), branch: 'main', ...(sha ? { sha } : {}) }),
    });
    if (r.ok) return;
    if (r.status === 409 || r.status === 422) continue; // 동시에 다른 글이 저장됨 → 다시 읽고 재시도
    throw new Error('GitHub write ' + r.status);
  }
  throw new UserError('동시에 글이 몰렸습니다. 잠시 뒤 다시 시도하십시오.', 503);
}

/* ── 비밀번호: PBKDF2(비밀번호, 글마다 다른 salt + 서버 PEPPER) ── */
async function hashPw(pw, salt, env) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(salt + '|' + (env.PEPPER || '')), iterations: PBKDF2_ITER }, key, 256);
  return toHex(new Uint8Array(bits));
}
async function checkPw(r, pw, env) { return timingSafeEq(await hashPw(pw, r.salt, env), r.pw); }

function timingSafeEq(a, b) {
  a = String(a); b = String(b);
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}
async function sha256Hex(s) { return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))); }
const toHex = (u8) => [...u8].map((x) => x.toString(16).padStart(2, '0')).join('');
function randomId(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return toHex(a).slice(0, n * 2 > 32 ? 32 : n * 2); }
function b64encode(str) { const bytes = new TextEncoder().encode(str); let bin = ''; for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000)); return btoa(bin); }
function b64decode(b64) { return new TextDecoder().decode(Uint8Array.from(atob(b64.replace(/\s/g, '')), (c) => c.charCodeAt(0))); }
