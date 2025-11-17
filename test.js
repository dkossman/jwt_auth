// test.js
import assert from 'assert';
import test from 'node:test';
import app, { redisClient } from './index.js'

let listener;
const BASE_URL = 'http://localhost:3000';
let token = '';
let cookie = '';
let newCookie=''; // To save new cookie after revoke

test.before(async () => {
  listener = await new Promise((resolve) => {
    const server = app.listen(3000, () => {
      console.log('Test server running on http://localhost:3000');
      resolve(server); // <- resolve with the server instance
    });
  });
});

test.after(async () => {
  // Wait until server is fully closed
  await new Promise((resolve, reject) => {
    listener.close((err) => (err ? reject(err) : resolve()));
  });

  // Disconnect redis
  await redisClient.quit();
});

// OUR TEST
test('Login and receive JWT token', async () => {
  const res = await fetch(`${BASE_URL}/login`, {
    method: 'GET',
  });

  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.ok(data.token, 'Token should be returned');
  token = data.token; // Save token for next test

  // In unit/integration tests, when the server sets an HTTP-only cookie (like a refresh token), 
  // it doesn't get stored or resent automatically between requests like a browser would.
  const setCookie = res.headers.get('set-cookie');
  cookie = setCookie;
});

// This will revoke refresh token (token variable)
// access token is still valid --> in production we would also revoke access token
test('Issue new access token', async()=>{
  assert.ok(cookie, 'Refresh token cookie should be set');
  const res = await fetch(`${BASE_URL}/refresh`, {
    method:"GET",
    headers: {
      Cookie: cookie,
    }
  })
  const setCookie = res.headers.get('set-cookie');
  newCookie = setCookie; // Save new refresh token cookie to get new access token
  assert.strictEqual(res.status, 200);
})

test('Use old refresh token to issue new token', async()=>{
    assert.ok(cookie, 'Refresh token cookie should be set');
    const res = await fetch(`${BASE_URL}/refresh`, {
        method:"GET",
        headers: {
        Cookie: cookie,
        }
    })
    assert.strictEqual(res.status, 403);
})

test('Access protected route with token', async () => {
  assert.ok(token, 'Token must be available from previous test');
  const res = await fetch(`${BASE_URL}/protected`, {
    method:"GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  assert.strictEqual(res.status, 200);
});

test('Access protected route with expired token', async()=>{
  // Wait for token to expire before making the request
  await new Promise(resolve => setTimeout(resolve, 0.5*60*1000));

  const res = await fetch(`${BASE_URL}/protected`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  assert.strictEqual(res.status, 401);
});

test('Get new access token', async()=>{
  assert.ok(cookie, 'Refresh token cookie should be set');
  const res = await fetch(`${BASE_URL}/refresh`, {
    method:"GET",
    headers: {
      Cookie: newCookie, // use new refresh token inside newCookie, using old one give 403
    }
  })
  assert.strictEqual(res.status, 200);
  const data = await res.json();
  token = data.token; // Save new token for next test
})

test('Access protected route with NEW token', async () => {
  assert.ok(token, 'Token must be available from previous test');
  const res = await fetch(`${BASE_URL}/protected`, {
    method:"GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  assert.strictEqual(res.status, 200);
});

test('Revoke refresh token', async()=>{
  const res=await fetch(`${BASE_URL}/revoke`, {
    method:"POST",
    headers: {
      Cookie: cookie,
    }
  })
  assert.strictEqual(res.status, 200)
})

test('Get new Access Token after Revoke', async()=>{
  const res = await fetch(`${BASE_URL}/refresh`, {
    method:"GET",
    headers: {
      Cookie: cookie,
    }
  })
  assert.strictEqual(res.status, 403);
})
