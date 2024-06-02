import { Hono } from 'hono';
import { Context, Next } from 'hono';
import { serve } from '@hono/node-server';
import { nanoid } from 'nanoid';
import * as jose from 'jose';
import 'dotenv/config';
import crypto from 'crypto';

const app = new Hono();

const clients = new Map<string, string>(); // { clientId: redirectUri }
const users = new Map<string, string>(); // { username: password }
const authCodes = new Map<string, any>(); // { authCode: { code_challenge, code_challenge_method, client_id, redirect_uri } }
clients.set('gemba', 'http://localhost/callback');
users.set('user', 'pass');

app.get('/', (c) => c.text('Authorization Server'));

app.get('/authorize', async (c) => {
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method } = c.req.query();

  if (!clients.has(client_id) || clients.get(client_id) !== redirect_uri) {
    return c.text('Invalid client', 400);
  }

  return c.html(`
    <form method="POST" action="/login">
      <input type="hidden" name="client_id" value="${client_id}" />
      <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
      <input type="hidden" name="state" value="${state}" />
      <input type="hidden" name="code_challenge" value="${code_challenge}" />
      <input type="hidden" name="code_challenge_method" value="${code_challenge_method}" />
      <label>Username: <input type="text" name="username" /></label>
      <label>Password: <input type="password" name="password" /></label>
      <button type="submit">Login</button>
    </form>
  `);
});

app.post('/login', async (c) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, username, password } = await c.req.parseBody();

  if (!users.has(username as string) || users.get(username as string) !== password) {
    return c.text('Invalid credentials', 401);
  }

  const code = nanoid();
  authCodes.set(code, { code_challenge, code_challenge_method, client_id, redirect_uri });

  const redirectUrl = new URL(redirect_uri as string);
  redirectUrl.searchParams.set('code', code);
  if (state && state !== 'undefined') {
    redirectUrl.searchParams.set('state', state as string);
  }
  return c.redirect(redirectUrl.toString());
});

app.post('/token', async (c) => {
  const { grant_type, code, redirect_uri, client_id, code_verifier } = await c.req.parseBody();

  if (grant_type !== 'authorization_code') {
    return c.text('Unsupported grant type', 400);
  }

  const storedData = authCodes.get(code as string);
  if (!storedData || storedData.client_id !== client_id || storedData.redirect_uri !== redirect_uri) {
    return c.text('Invalid code', 400);
  }

  // PKCEの検証
  const expectedHash = crypto.createHash('sha256').update(code_verifier as string).digest('base64url');
  if (expectedHash !== storedData.code_challenge) {
    return c.text('Invalid code verifier', 400);
  }

  const privateKey = await jose.importPKCS8(process.env.PRIVATE_KEY!, 'RS256');
  const jwt = await new jose.SignJWT({ 'urn:example:claim': true })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuedAt()
    .setIssuer('urn:example:issuer')
    .setAudience(client_id as string)
    .setExpirationTime('2h')
    .sign(privateKey);

  return c.json({ access_token: jwt, token_type: 'Bearer' });
});

// アクセストークンの検証ミドルウェア
const verifyToken = async (c: Context, next: Next) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.text('Forbidden', 403);
  }

  const token = authHeader.split(' ')[1];
  try {
    const publicKey = await jose.importSPKI(process.env.PUBLIC_KEY!.replace(/\\n/g, '\n'), 'RS256');
    const { payload } = await jose.jwtVerify(token, publicKey, {
      issuer: 'urn:example:issuer',
    });

    await next();
  } catch (error) {
    return c.text('Forbidden', 403);
  }
};

app.post('/echo', verifyToken, async (c) => {
  const requestBody = await c.req.json();
  const prettyJson = JSON.stringify(requestBody, null, 2);
  return c.json({ message: prettyJson });
});

serve(app);
