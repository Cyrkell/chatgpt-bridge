#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Cyrkell Authors
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing permissions and limitations under the
// License.
//
// Source: https://github.com/Cyrkell/chatgpt-bridge
//
// Cyrkell's ChatGPT bridge: ChatGPT answers on your Cyrkell relay with your own ChatGPT plan, through
// OpenAI's "Sign in with ChatGPT". It runs on your computer and keeps your ChatGPT sign-in there: the
// relay never sees it. It needs Node.js 20 or later, and nothing else.
//
//   node cyrkell-chatgpt.mjs login                     sign in (your browser opens: Continue with ChatGPT)
//   node cyrkell-chatgpt.mjs run <ChatGPT connector link> [--as chatgpt-plan] [--model <id>] [--answer-ais]
//   node cyrkell-chatgpt.mjs status | models | logout
//
// It follows OpenAI's documentation for open-source and locally hosted apps:
// - Sign-in registers "Cyrkell" as your agent, with OAuth and PKCE, a callback on 127.0.0.1, and a
//   stable id for this computer (an RFC 9278 key thumbprint). No client secret, no API key.
// - Your tokens stay in files only you can read (~/.config/cyrkell/chatgpt). The bridge refreshes
//   them before they expire and revokes them when you log out.
// - It answers your own messages on the relay, and the loops you start, with the Responses API
//   (store: false, stream: true). Requests from your other AIs only with --answer-ais, which asks for
//   your consent first.
// - When your plan's limit is reached it stops asking OpenAI for a while and says so on the relay,
//   with a link to ChatGPT's usage settings.

import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdir, open, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

export const VERSION = '1.0.0';
export const APP_NAME = 'Cyrkell';
export const AUTH = 'https://auth.openai.com';
export const API = 'https://api.openai.com/v1';
export const USAGE_URL = 'https://chatgpt.com/settings/usage';
const RESOURCE = 'https://api.openai.com/v1';
const SCOPE = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct';
const PLAN_SCOPE = 'chatgpt.tokens.use.direct';
const CALLBACK_PATH = '/auth/callback';
const DEFAULT_PORT = 1455;
const SIGN_IN_TIMEOUT_MS = 10 * 60_000;
const REFRESH_MARGIN_MS = 5 * 60_000; // refresh when the access token has less than this left
const LIMIT_PAUSE_MS = 30 * 60_000; // after a usage-limit answer, how long to stop asking OpenAI
const RETRY_DELAYS_MS = [5_000, 20_000, 60_000]; // for "try again later" answers
const POLL_ACTIVE_MS = 3_000; // inbox checks soon after work
const POLL_IDLE_MS = 10_000;
const ACTIVE_FOR_MS = 2 * 60_000;
const BODY_LIMIT = 60_000; // the relay's longest message

// ---------- small helpers ----------

export class BridgeError extends Error {
  constructor(message, hint = '', extra = {}) {
    super(message);
    this.hint = hint;
    Object.assign(this, extra);
  }
}

export const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const fromB64url = (text) => new Uint8Array(Buffer.from(String(text), 'base64url'));
const random = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest('SHA-256', typeof data === 'string' ? new TextEncoder().encode(data) : data));
const iso = (ms) => new Date(ms).toISOString();
const sleep = (ms, signal) =>
  new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => (clearTimeout(timer), resolve()), { once: true });
  });

/** PKCE (RFC 7636): a random verifier and its S256 challenge. */
export async function pkce(verifier = random(32)) {
  return { verifier, challenge: b64url(await sha256(verifier)) };
}

// RFC 7638: a JWK's thumbprint is the SHA-256 of its required members, in lexicographic order,
// without whitespace. RFC 9278 makes it a URI, the host id OpenAI recommends.
const THUMBPRINT_MEMBERS = { EC: ['crv', 'kty', 'x', 'y'], RSA: ['e', 'kty', 'n'], OKP: ['crv', 'kty', 'x'] };

export async function jwkThumbprint(jwk) {
  const members = THUMBPRINT_MEMBERS[jwk.kty];
  if (!members) throw new Error(`no thumbprint for key type ${jwk.kty}`);
  return b64url(await sha256(`{${members.map((k) => `${JSON.stringify(k)}:${JSON.stringify(jwk[k])}`).join(',')}}`));
}

export const thumbprintUri = async (jwk) => `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${await jwkThumbprint(jwk)}`;

// ---------- local storage, readable only by you ----------

export function defaultDir(env = process.env) {
  if (env.CYRKELL_BRIDGE_DIR) return env.CYRKELL_BRIDGE_DIR;
  const base = platform() === 'win32' ? env.APPDATA || join(homedir(), 'AppData', 'Roaming') : env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(base, 'cyrkell', 'chatgpt');
}

export class Store {
  constructor(dir) {
    this.dir = dir;
  }

  path(name) {
    return join(this.dir, name);
  }

  async read(name, fallback = null) {
    try {
      return JSON.parse(await readFile(this.path(name), 'utf8'));
    } catch (error) {
      if (error.code === 'ENOENT') return fallback;
      throw error;
    }
  }

  /** Written whole or not at all (a temporary file, then a rename), with owner-only permissions. */
  async write(name, value) {
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    const target = this.path(name);
    const temp = `${target}.${random(6)}.tmp`;
    await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    await rename(temp, target);
  }
}

const accountFile = (clientId) => `account-${String(clientId).replace(/[^A-Za-z0-9_.-]/g, '_')}.json`;

/** This computer's host id: made once, before its first sign-in, and kept. */
export async function hostId(store) {
  const saved = await store.read('host.json');
  if (saved?.ext_agent_host_id) return saved.ext_agent_host_id;
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const id = await thumbprintUri({ kty, crv, x, y });
  // OpenAI does not check possession of the key yet; it is kept in case it does.
  await store.write('host.json', { ext_agent_host_id: id, public_jwk: { kty, crv, x, y }, private_jwk: await crypto.subtle.exportKey('jwk', pair.privateKey), created_at: new Date().toISOString() });
  return id;
}

/** Only one process refreshes at a time: refresh tokens rotate, and a race would spend one twice. */
async function withLock(store, fn) {
  await mkdir(store.dir, { recursive: true, mode: 0o700 });
  const lock = store.path('refresh.lock');
  for (let tries = 0; ; tries++) {
    try {
      await (await open(lock, 'wx', 0o600)).close();
      break;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const age = Date.now() - ((await stat(lock).catch(() => null))?.mtimeMs ?? 0);
      if (age > 60_000) await rm(lock, { force: true });
      else if (tries > 200) throw new BridgeError('Another bridge process is renewing the sign-in.', 'Try again in a minute.');
      else await sleep(100);
    }
  }
  try {
    return await fn();
  } finally {
    await rm(lock, { force: true });
  }
}

// ---------- OpenAI sign-in ----------

async function getJson(net, url) {
  const res = await net(url, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new BridgeError(`${new URL(url).host} answered ${res.status}.`, 'Check your connection and try again.');
  return res.json();
}

async function discovery(net) {
  const doc = await getJson(net, `${AUTH}/.well-known/openid-configuration`);
  if (doc.issuer !== AUTH) throw new BridgeError(`Unexpected issuer ${doc.issuer}.`);
  return doc;
}

const ALGS = {
  RS256: { key: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verify: { name: 'RSASSA-PKCS1-v1_5' } },
  ES256: { key: { name: 'ECDSA', namedCurve: 'P-256' }, verify: { name: 'ECDSA', hash: 'SHA-256' } },
};

/** Checks an ID token: OpenAI's signature, the issuer, this client as audience, expiry and the nonce. */
export async function verifyIdToken(net, token, { clientId, nonce, now, doc }) {
  const [h, p, s] = String(token ?? '').split('.');
  if (!s) throw new BridgeError('The ID token is not a signed token.');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
  const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  const alg = ALGS[header.alg];
  if (!alg) throw new BridgeError(`The ID token uses ${header.alg}, which the bridge does not accept.`);
  const keys = (await getJson(net, doc.jwks_uri)).keys ?? [];
  const jwk = keys.find((k) => k.kid === header.kid) ?? (keys.length === 1 && !header.kid ? keys[0] : null);
  if (!jwk) throw new BridgeError('The ID token was not signed with one of OpenAI’s published keys.');
  const { kty, n, e, crv, x, y } = jwk;
  const key = await crypto.subtle.importKey('jwk', kty === 'RSA' ? { kty, n, e } : { kty, crv, x, y }, alg.key, false, ['verify']);
  if (!(await crypto.subtle.verify(alg.verify, key, fromB64url(s), new TextEncoder().encode(`${h}.${p}`)))) throw new BridgeError('The ID token’s signature does not verify.');
  if (claims.iss !== doc.issuer) throw new BridgeError(`The ID token comes from ${claims.iss}, not ${doc.issuer}.`);
  if (!(Array.isArray(claims.aud) ? claims.aud : [claims.aud]).includes(clientId)) throw new BridgeError('The ID token was issued to another client.');
  if (typeof claims.exp !== 'number' || claims.exp * 1000 < now - 60_000) throw new BridgeError('The ID token has expired.');
  if (claims.nonce !== nonce) throw new BridgeError('The ID token does not belong to this sign-in (nonce).');
  if (!claims.sub) throw new BridgeError('The ID token names no account.');
  return claims;
}

async function tokenRequest(net, form) {
  const res = await net(`${AUTH}/api/accounts/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams(form).toString(),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new BridgeError(`OpenAI’s sign-in answered ${res.status}${data.error ? ` (${data.error})` : ''}.`, '', { status: res.status, code: data.error ?? data.code ?? null });
  if (!data.access_token) throw new BridgeError('OpenAI’s sign-in sent no access token.');
  return data;
}

const scopesOf = (text) => String(text ?? '').split(/\s+/).filter(Boolean).sort();
const whenMs = (value) => (value == null ? null : typeof value === 'number' ? (value < 1e12 ? value * 1000 : value) : Date.parse(value) || null);

/** The fields of a token response, as kept in the account's file. */
function tokenFields(tokens, now, before = {}) {
  const scopes = tokens.scope ? scopesOf(tokens.scope) : before.scopes ?? [];
  const earliest = whenMs(tokens.earliest_refresh_at);
  return {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token ?? before.refresh_token ?? '',
    id_token: tokens.id_token ?? before.id_token ?? '',
    token_type: tokens.token_type ?? 'Bearer',
    expires_in: tokens.expires_in ?? 3600,
    scopes,
    plan: scopes.includes(PLAN_SCOPE),
    saved_at: iso(now),
    expires_at: iso(now + (tokens.expires_in ?? 3600) * 1000),
    earliest_refresh_at: earliest ? iso(earliest) : null,
  };
}

/** Listens on 127.0.0.1 for the browser's return; only the port may vary. */
function listenCallback(state, port) {
  return new Promise((resolve, reject) => {
    let settle;
    let fail;
    const result = new Promise((ok, no) => ((settle = ok), (fail = no)));
    const server = createServer((req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1');
      if (url.pathname !== CALLBACK_PATH) return res.writeHead(404).end();
      // Anything else that reaches this port without this attempt's state is turned away.
      if (url.searchParams.get('state') !== state) return res.writeHead(400, { 'content-type': 'text/plain' }).end('This sign-in link is not for this attempt.');
      const ok = !url.searchParams.get('error');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(`<!doctype html><meta charset="utf-8"><title>${APP_NAME}</title><body style="font:16px system-ui;margin:3em"><p>${ok ? 'Signed in. You can close this tab and go back to the terminal.' : 'The sign-in did not complete. Go back to the terminal.'}</p>`);
      settle(url.searchParams);
    });
    const timer = setTimeout(() => fail(new BridgeError('The sign-in timed out.', 'Run login again.')), SIGN_IN_TIMEOUT_MS);
    const close = () => (clearTimeout(timer), server.close());
    const listen = (p) => {
      server.once('error', (error) => (p && error.code === 'EADDRINUSE' ? listen(0) : reject(error)));
      server.listen(p, '127.0.0.1', () => resolve({ uri: `http://127.0.0.1:${server.address().port}${CALLBACK_PATH}`, result, close }));
    };
    listen(port);
  });
}

/** Opens the system browser, without a shell. */
export function openBrowser(url) {
  const [cmd, args] = platform() === 'darwin' ? ['open', [url]] : platform() === 'win32' ? ['rundll32', ['url.dll,FileProtocolHandler', url]] : ['xdg-open', [url]];
  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', () => {});
    child.unref();
  } catch {}
}

/**
 * Sign in with ChatGPT. The first time, registers this app with client_id=dynamic_agent_client and
 * keeps the client id OpenAI issues; later, signs in again with that id. `fresh` registers another
 * account. Returns { record, welcome } or { declined }.
 */
export async function login(ctx, { fresh = false, port = DEFAULT_PORT } = {}) {
  const host = await hostId(ctx.store);
  const state = await ctx.store.read('state.json', {});
  const existing = !fresh && state.active ? await ctx.store.read(accountFile(state.active)) : null;
  const { verifier, challenge } = await pkce();
  const attempt = { state: random(24), nonce: random(24) };
  const callback = await listenCallback(attempt.state, port);
  let params;
  try {
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: existing?.client_id ?? 'dynamic_agent_client',
      ...(existing ? {} : { agent_name_hint: APP_NAME }),
      ext_agent_host_id: host,
      redirect_uri: callback.uri,
      scope: SCOPE,
      resource: RESOURCE,
      state: attempt.state,
      nonce: attempt.nonce,
      code_challenge_method: 'S256',
      code_challenge: challenge,
      ...(existing?.email ? { login_hint: existing.email } : {}),
    });
    // The printed address leaves out the ID token hint: it must not reach logs.
    ctx.log(`Continue with ChatGPT in your browser. If it did not open, go to:\n${AUTH}/api/accounts/authorize?${query}\n`);
    if (existing?.id_token) query.set('id_token_hint', existing.id_token);
    ctx.openBrowser(`${AUTH}/api/accounts/authorize?${query}`);
    params = await callback.result;
  } finally {
    callback.close();
  }
  const error = params.get('error');
  if (error === 'access_denied') return { declined: true };
  if (error) throw new BridgeError(`The sign-in failed: ${error}${params.get('error_description') ? ` (${params.get('error_description')})` : ''}.`, 'Run login again.');
  const issued = params.get('client_id');
  let clientId;
  if (existing) {
    if (issued && issued !== existing.client_id) throw new BridgeError('The sign-in came back for another registration; nothing was replaced.', 'Run login again.');
    clientId = existing.client_id;
  } else {
    if (!issued || issued === 'dynamic_agent_client') throw new BridgeError('The registration did not complete: no client id came back.', 'Run login again.');
    clientId = issued;
  }
  const code = params.get('code');
  if (!code) throw new BridgeError('The sign-in came back without a code.', 'Run login again.');
  const tokens = await tokenRequest(ctx.net, { grant_type: 'authorization_code', client_id: clientId, code, code_verifier: verifier, redirect_uri: callback.uri, resource: RESOURCE });
  const now = ctx.now();
  const claims = await verifyIdToken(ctx.net, tokens.id_token, { clientId, nonce: attempt.nonce, now, doc: await discovery(ctx.net) });
  if (existing?.subject && claims.sub !== existing.subject) throw new BridgeError('You signed in as another ChatGPT account; nothing was replaced.', 'To add that account, run: login --new');
  const record = { email: claims.email ?? existing?.email ?? '', issuer: claims.iss, subject: claims.sub, client_id: clientId, ext_agent_host_id: host, ...tokenFields(tokens, now) };
  await ctx.store.write(accountFile(clientId), record);
  const welcome = record.plan && !state.welcomed;
  await ctx.store.write('state.json', { ...state, active: clientId, welcomed: Boolean(state.welcomed || record.plan) });
  return { record, welcome };
}

/** The active account, refreshed first when its access token is near its end. */
export async function account(ctx, { force = false } = {}) {
  const state = await ctx.store.read('state.json', {});
  if (!state.active) throw new BridgeError('You are not signed in to ChatGPT.', 'Run: node cyrkell-chatgpt.mjs login');
  const file = accountFile(state.active);
  const due = (r) => force || Date.parse(r.expires_at) - ctx.now() < REFRESH_MARGIN_MS;
  let record = await ctx.store.read(file);
  if (!record?.access_token) throw new BridgeError('You are signed out of ChatGPT.', 'Run: node cyrkell-chatgpt.mjs login');
  if (!due(record) || (!force && record.earliest_refresh_at && ctx.now() < Date.parse(record.earliest_refresh_at) && Date.parse(record.expires_at) > ctx.now())) return record;
  return withLock(ctx.store, async () => {
    record = await ctx.store.read(file);
    if (!record?.access_token) throw new BridgeError('You are signed out of ChatGPT.', 'Run: node cyrkell-chatgpt.mjs login');
    if (!due(record)) return record; // another process renewed it meanwhile
    let tokens;
    try {
      tokens = await tokenRequest(ctx.net, { grant_type: 'refresh_token', client_id: record.client_id, refresh_token: record.refresh_token, resource: RESOURCE });
    } catch (error) {
      if (['invalid_grant', 'invalid_refresh_token', 'token_expired', 'refresh_token_expired', 'refresh_token_invalidated', 'refresh_token_reused'].includes(error.code)) {
        const { access_token, refresh_token, ...kept } = record;
        await ctx.store.write(file, { ...kept, signed_out_at: iso(ctx.now()), signed_out_because: error.code });
        throw new BridgeError('Your ChatGPT sign-in has ended.', 'Run: node cyrkell-chatgpt.mjs login', { kind: 'auth' });
      }
      if (error.code === 'invalid_client') throw new BridgeError('OpenAI no longer knows this registration.', 'Run: node cyrkell-chatgpt.mjs login --new', { kind: 'auth' });
      throw Object.assign(error, { kind: 'retry' }); // a network or server problem: the tokens stay
    }
    const next = { ...record, ...tokenFields(tokens, ctx.now(), record) };
    await ctx.store.write(file, next);
    return next;
  });
}

/** Ends the sign-in: revokes the refresh token at OpenAI, then forgets the tokens here. */
export async function logout(ctx) {
  const state = await ctx.store.read('state.json', {});
  const record = state.active ? await ctx.store.read(accountFile(state.active)) : null;
  if (!record?.access_token && !record?.refresh_token) return { already: true };
  let revoked = false;
  const doc = record.refresh_token ? await discovery(ctx.net).catch(() => null) : null;
  for (let i = 0; doc?.revocation_endpoint && !revoked && i < 3; i++) {
    try {
      const res = await ctx.net(doc.revocation_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: record.refresh_token, token_type_hint: 'refresh_token', client_id: record.client_id }).toString(),
      });
      if (res.status === 200) revoked = true;
      else if (res.status < 500) break;
    } catch {}
    if (!revoked && i < 2) await ctx.sleep(1000 * 2 ** i);
  }
  // The account's client id and this computer's id stay, for the next sign-in.
  const { access_token, refresh_token, id_token, ...kept } = record;
  await ctx.store.write(accountFile(record.client_id), { ...kept, signed_out_at: iso(ctx.now()) });
  return { revoked };
}

// ---------- ChatGPT plan requests (the Responses API) ----------

/** What each plan error means for the bridge, from OpenAI's errors-and-recovery guide. */
const PLAN_ERRORS = {
  subscription_sharing_usage_limit_exceeded: 'limit',
  subscription_sharing_usage_unavailable: 'retry',
  subscription_sharing_user_unavailable: 'retry',
  subscription_sharing_user_not_eligible: 'fatal',
  subscription_sharing_route_not_supported: 'fatal',
  subscription_sharing_unsupported_capability: 'request',
  subscription_sharing_invalid_user: 'auth',
  chatpass_v2_scope_not_authorized: 'fatal',
  chatpass_v2_invalid_authorization_context: 'fatal',
};

export function planError({ status = 0, code = null, param = null, message = '', requestId = null }) {
  const kind = PLAN_ERRORS[code] ?? (status === 401 ? 'auth' : status === 429 || status >= 500 || status === 0 ? 'retry' : status === 403 ? 'fatal' : 'request');
  const detail = [code, param && `(${param})`, message].filter(Boolean).join(' ');
  const text = `ChatGPT answered ${status || 'nothing'}${detail ? `: ${detail}` : ''}`;
  return new BridgeError(/[.!?]$/.test(text) ? text : `${text}.`, '', { kind, status, code, param, requestId });
}

async function failedResponse(res) {
  const raw = await res.text().catch(() => '');
  let body = {};
  try {
    body = JSON.parse(raw);
  } catch {}
  // Admission can answer {"detail": "..."} before a Responses request starts.
  return planError({ status: res.status, code: body.error?.code ?? null, param: body.error?.param ?? null, message: String(body.error?.message ?? body.detail ?? raw).slice(0, 300), requestId: res.headers.get('x-request-id') });
}

async function* serverEvents(stream) {
  const decoder = new TextDecoder();
  let buffer = '';
  for await (const chunk of stream) {
    buffer += decoder.decode(chunk, { stream: true });
    for (let m = /\r?\n\r?\n/.exec(buffer); m; m = /\r?\n\r?\n/.exec(buffer)) {
      const data = buffer
        .slice(0, m.index)
        .split(/\r?\n/)
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).replace(/^ /, ''));
      buffer = buffer.slice(m.index + m[0].length);
      if (data.length) yield data.join('\n');
    }
  }
}

/** One turn of the relay's conversation as a Responses input item. */
export function inputItem(turn) {
  if (turn.role === 'assistant') return { role: 'assistant', content: turn.parts.map((p) => p.text ?? '').join('\n\n') };
  return {
    role: 'user',
    content: turn.parts.map((part) => {
      if (part.kind === 'image') return { type: 'input_image', image_url: `data:${part.mime};base64,${part.data}` };
      if (part.kind === 'pdf') return { type: 'input_file', filename: part.name, file_data: `data:application/pdf;base64,${part.data}` };
      return { type: 'input_text', text: part.text };
    }),
  };
}

/** The models this ChatGPT account may use, in OpenAI's order: [{ id, name }]. */
export async function listModels(ctx, record) {
  const res = await ctx.net(`${API}/models`, { headers: { authorization: `Bearer ${record.access_token}`, accept: 'application/json' } });
  if (!res.ok) throw await failedResponse(res);
  const data = await res.json();
  if (Array.isArray(data.models)) return data.models.filter((m) => m.visibility === 'list').map((m) => ({ id: m.slug, name: m.display_name || m.slug }));
  return (data.data ?? []).map((m) => ({ id: m.id, name: m.id }));
}

/**
 * Asks ChatGPT, on the user's plan, and reads the stream to its end. Only response.completed is a
 * complete answer; an incomplete one comes back with `incomplete` set. Instructions go in
 * `instructions` (system items are refused), and none of the fields the plan does not accept are sent.
 */
export async function ask(ctx, record, { model, system, turns }) {
  const res = await ctx.net(`${API}/responses`, {
    method: 'POST',
    headers: { authorization: `Bearer ${record.access_token}`, 'content-type': 'application/json', accept: 'text/event-stream' },
    body: JSON.stringify({ model, instructions: system, input: turns.map(inputItem), store: false, stream: true }),
  });
  if (!res.ok) throw await failedResponse(res);
  let text = '';
  for await (const data of serverEvents(res.body)) {
    if (data === '[DONE]') continue;
    let event;
    try {
      event = JSON.parse(data);
    } catch {
      continue;
    }
    if (event.type === 'response.output_text.delta') text += event.delta ?? '';
    else if (event.type === 'response.completed') return { text: text || outputText(event.response), model: event.response?.model ?? model };
    else if (event.type === 'response.incomplete') return { text, model: event.response?.model ?? model, incomplete: event.response?.incomplete_details?.reason ?? 'incomplete' };
    else if (event.type === 'response.failed') throw planError({ status: 200, code: event.response?.error?.code, message: event.response?.error?.message });
    else if (event.type === 'error') throw planError({ status: 200, code: event.code ?? event.error?.code, param: event.param ?? event.error?.param, message: event.message ?? event.error?.message });
  }
  throw new BridgeError('The answer stopped before it was complete.', '', { kind: 'retry' });
}

const outputText = (response) =>
  (response?.output ?? [])
    .flatMap((item) => item.content ?? [])
    .filter((c) => c.type === 'output_text')
    .map((c) => c.text)
    .join('');

// ---------- the relay ----------

/** The relay, reached with its ChatGPT connector link (the part after /mcp/ is the key). */
export class Relay {
  constructor(link, net) {
    let url;
    try {
      url = new URL(String(link));
    } catch {
      throw new BridgeError('That is not a connector link.', 'Copy the ChatGPT connector link from your relay: Setup → 1 · Connect your AIs.');
    }
    const m = url.pathname.match(/^(.*)\/mcp\/([A-Za-z0-9_-]{8,200})$/);
    if (!m || !/^https?:$/.test(url.protocol)) throw new BridgeError('That is not a connector link.', 'Copy the ChatGPT connector link from your relay: Setup → 1 · Connect your AIs.');
    this.origin = url.origin;
    this.base = `${url.origin}${m[1]}`;
    this.key = m[2];
    this.net = net;
  }

  async call(method, path, body) {
    const res = await this.net(`${this.base}${path}`, {
      method,
      headers: { authorization: `Bearer ${this.key}`, accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({ ok: false, error: `HTTP ${res.status}` }));
    if (!data.ok) throw new BridgeError(`The relay answered: ${data.error}`, data.hint ?? '', { status: res.status });
    return data.data;
  }
}


/**
 * Answers the relay as one role until `signal` aborts (or after one look at the inbox with `once`).
 * ctx = { net, store, now, sleep, log }.
 */
export async function serve(ctx, { link, as = 'chatgpt-plan', model: wanted = '', answerAIs = false, once = false, signal } = {}) {
  const relay = new Relay(link, ctx.net);
  const health = await ctx.net(`${relay.origin}/health`).then((r) => r.json()).catch(() => ({}));
  if (health.hosted) throw new BridgeError('Sign in with ChatGPT is not available on the hosted service yet.', 'OpenAI must first approve it for hosted apps; it works with a relay you run yourself.');
  let record = await account(ctx);
  if (!record.plan) throw new BridgeError('This sign-in does not allow Cyrkell to use your ChatGPT plan.', 'Run login again and allow it, or give ChatGPT an OpenAI API key on the relay instead.');
  const models = await listModels(ctx, record);
  const model = wanted ? models.find((m) => m.id === wanted) : models[0];
  if (!model) throw new BridgeError(wanted ? `Your ChatGPT plan does not offer ${wanted}.` : 'Your ChatGPT plan lists no models.', models.length ? `Choose one of: ${models.map((m) => m.id).join(', ')}` : '');
  const hello = await relay.call('POST', '/api/v1/bridge', { as, model: model.id, model_name: model.name, answer_ais: answerAIs, version: VERSION });
  // A fresh session: the next inbox brings the owner's instructions with it.
  await relay.call('POST', '/api/v1/done', { as });
  ctx.log(`Answering as ${hello.name} on ${relay.base}, with ${model.name}, on your ChatGPT plan${answerAIs ? ' (your other AIs’ requests too)' : ''}. Manage usage: ${USAGE_URL}`);

  // A usage limit pauses requests to ChatGPT for a while, kept across restarts.
  let limitedUntil = Date.parse((await ctx.store.read('state.json', {})).limited_until ?? '') || 0;
  let activeAt = ctx.now();
  const reply = (c, body) => relay.call('POST', '/api/v1/send', { as, ...c.reply, body });
  // A request it could not answer gets a BLOCK, as the relay's own API answers do.
  const notice = (c, text) => relay.call('POST', '/api/v1/send', { as, ...c.reply, type: 'BLOCK', body: `(Not answered: ${text})` });
  const limitText = `your ChatGPT plan’s usage limit for ${APP_NAME} was reached. Review it in ChatGPT: Manage usage, ${USAGE_URL}`;
  const stop = (error) => Object.assign(error, { stop: true });

  async function answer(m) {
    const c = await relay.call('POST', '/api/v1/conversation', { as, message: m.id });
    if (!c.answer) return ctx.log(`${m.id}: not answered (${c.reason}).`);
    activeAt = ctx.now();
    if (ctx.now() < limitedUntil) return void (await notice(c, limitText));
    ctx.log(`${m.id}: answering…`);
    let out;
    for (let attempt = 0, renewed = false; ; attempt++) {
      try {
        out = await ask(ctx, record, { model: model.id, system: c.system, turns: c.turns });
        break;
      } catch (error) {
        if (error.kind === 'auth' && !renewed) {
          renewed = true;
          record = await account(ctx, { force: true });
          continue;
        }
        if (error.kind === 'retry' && attempt < RETRY_DELAYS_MS.length) {
          await ctx.sleep(RETRY_DELAYS_MS[attempt], signal);
          continue;
        }
        if (error.kind === 'limit') {
          limitedUntil = ctx.now() + LIMIT_PAUSE_MS;
          await ctx.store.write('state.json', { ...(await ctx.store.read('state.json', {})), limited_until: iso(limitedUntil) });
          await notice(c, limitText);
          ctx.log(`Usage limit reached: no requests to ChatGPT for ${LIMIT_PAUSE_MS / 60_000} minutes. Manage usage: ${USAGE_URL}`);
          return;
        }
        const what = error.kind === 'request' ? `ChatGPT refused the request (${error.code ?? error.status}${error.param ? `: ${error.param}` : ''})` : error.message.replace(/\.$/, '');
        await notice(c, `${what}.`).catch(() => {});
        if (error.kind === 'auth' || error.kind === 'fatal') throw stop(error);
        return;
      }
    }
    let body = out.text.trim() || '(ChatGPT sent an empty answer.)';
    if (out.incomplete) body += `\n\n[Cut off: ${out.incomplete}]`;
    if (body.length > BODY_LIMIT - 100) body = `${body.slice(0, BODY_LIMIT - 100)}\n\n[Shortened: the answer was longer than a message may be.]`;
    try {
      await reply(c, body);
    } catch (error) {
      // The relay refuses anything that looks like a credential; say so instead of losing the turn.
      await notice(c, `the answer was withheld: ${error.message.replace(/^The relay answered: /, '')}`);
    }
    ctx.log(`${m.id}: answered (${body.length} characters).`);
  }

  let failed = false;
  try {
    while (!signal?.aborted) {
      record = await account(ctx).catch((error) => {
        if (error.kind === 'retry') return record;
        throw stop(error);
      });
      const box = await relay.call('GET', `/api/v1/inbox?as=${encodeURIComponent(as)}`);
      for (const m of box.messages ?? []) {
        if (signal?.aborted) break;
        try {
          await answer(m);
        } catch (error) {
          if (error.stop) throw error;
          ctx.log(`${m.id}: ${error.message}${error.hint ? ` ${error.hint}` : ''}`);
        }
      }
      if (once) break;
      await ctx.sleep(ctx.now() - activeAt < ACTIVE_FOR_MS ? POLL_ACTIVE_MS : POLL_IDLE_MS, signal);
    }
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    // The relay shows the bridge as stopped (one look at the inbox with `once` is not a stop).
    if (!once || failed) await relay.call('POST', '/api/v1/bridge', { as, stopped: true }).catch(() => {});
  }
}

// ---------- the command line ----------

const HELP = `${APP_NAME}'s ChatGPT bridge ${VERSION}: ChatGPT answers on your relay with your ChatGPT plan.

  login [--new]        Sign in with ChatGPT (your browser opens). --new adds another account.
  run <link>           Answer as a role on your relay. <link> is the ChatGPT connector link
                       from Setup → 1 · Connect your AIs.
      --as <role>        the role it answers as (default: chatgpt-plan)
      --model <id>       one of the models "models" lists (default: the first)
      --answer-ais       also answer your other AIs' requests, in the background (asks first)
  models               The models your ChatGPT plan offers.
  status               Who is signed in, and until when.
  logout               Sign out: revokes the sign-in at OpenAI and forgets it here.

Your sign-in is kept in ${defaultDir()} (set CYRKELL_BRIDGE_DIR to change it).
Manage your ChatGPT plan's usage: ${USAGE_URL}`;

async function consent(ctx, yes) {
  const state = await ctx.store.read('state.json', {});
  if (state.ais_consent_at) return true;
  let agreed = Boolean(yes);
  if (!agreed && process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const answer = await rl.question(`Let ${APP_NAME} use your ChatGPT plan to answer your other AIs' requests, in the background, while this bridge runs? [y/N] `);
    rl.close();
    agreed = /^y(es)?$/i.test(answer.trim());
  }
  if (agreed) await ctx.store.write('state.json', { ...state, ais_consent_at: iso(ctx.now()) });
  return agreed;
}

export async function main(argv, ctx = { net: fetch, store: new Store(defaultDir()), now: Date.now, sleep, log: console.log, openBrowser }) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { as: { type: 'string' }, model: { type: 'string' }, 'answer-ais': { type: 'boolean' }, yes: { type: 'boolean' }, new: { type: 'boolean' }, help: { type: 'boolean' } },
  });
  const [command, link] = positionals;
  if (!command || values.help || command === 'help') return ctx.log(HELP);
  if (command === 'login') {
    const done = await login(ctx, { fresh: values.new });
    if (done.declined) return ctx.log(`${APP_NAME} may not use your ChatGPT plan: nothing was saved. Run login again to allow it, or give ChatGPT an OpenAI API key on the relay instead.`);
    const r = done.record;
    ctx.log(`Signed in to ChatGPT as ${r.email || r.subject}.`);
    if (!r.plan) ctx.log(`${APP_NAME} may not use your ChatGPT plan with this sign-in. Run login again and allow it, or give ChatGPT an OpenAI API key on the relay instead.`);
    else if (done.welcome) ctx.log(`\nYou're using your ChatGPT plan. ChatGPT's answers on ${APP_NAME} now come from your ChatGPT plan, within its limits. Manage usage in ChatGPT: ${USAGE_URL}\n`);
    return ctx.log(`Next: node ${process.argv[1]?.split(/[\\/]/).pop() ?? 'cyrkell-chatgpt.mjs'} run <your ChatGPT connector link>`);
  }
  if (command === 'status') {
    const state = await ctx.store.read('state.json', {});
    const r = state.active ? await ctx.store.read(accountFile(state.active)) : null;
    if (!r) return ctx.log('Not signed in. Run login.');
    return ctx.log(
      [
        `ChatGPT account: ${r.email || r.subject}${r.access_token ? '' : ' (signed out)'}`,
        `Registration: ${r.client_id}; this computer: ${r.ext_agent_host_id}`,
        `Use of your ChatGPT plan: ${r.plan ? 'allowed' : 'not allowed (run login again to allow it)'}`,
        r.access_token ? `Access until ${r.expires_at} (renewed on its own while the bridge runs)` : '',
        `Manage usage: ${USAGE_URL}`,
      ]
        .filter(Boolean)
        .join('\n'),
    );
  }
  if (command === 'models') {
    const models = await listModels(ctx, await account(ctx));
    return ctx.log(models.map((m) => `${m.id}${m.name !== m.id ? `  (${m.name})` : ''}`).join('\n') || 'No models listed.');
  }
  if (command === 'logout') {
    const out = await logout(ctx);
    return ctx.log(out.already ? 'Already signed out.' : out.revoked ? 'Signed out: the sign-in is revoked at OpenAI and forgotten here.' : 'Signed out here. OpenAI did not confirm the revocation: to be sure, disconnect Cyrkell in ChatGPT → Settings → Apps.');
  }
  if (command === 'run') {
    if (!link) throw new BridgeError('Give the ChatGPT connector link.', 'Setup → 1 · Connect your AIs → ChatGPT, on your relay.');
    let answerAIs = Boolean(values['answer-ais']);
    if (answerAIs && !(await consent(ctx, values.yes))) {
      ctx.log('Without your consent the bridge answers only your own messages.');
      answerAIs = false;
    }
    const controller = new AbortController();
    for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => controller.abort());
    return serve(ctx, { link, as: values.as, model: values.model, answerAIs, signal: controller.signal });
  }
  throw new BridgeError(`Unknown command "${command}".`, 'Run with --help.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`${error.message}${error.hint ? `\n${error.hint}` : ''}`);
    process.exitCode = 1;
  });
}
