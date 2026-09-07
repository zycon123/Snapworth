import { test } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import request from 'supertest';
import { createApp } from '../server.js';

// Only the disposable CI database is accepted. Never run against application data.
test('PostgreSQL migration, persistent sessions and concurrent quotas', {skip: !process.env.TEST_DATABASE_URL}, async () => {
  const url = new URL(process.env.TEST_DATABASE_URL);
  assert.equal(url.pathname, '/snapworth_test');
  assert.ok(['localhost', '127.0.0.1'].includes(url.hostname));
  const pool = new pg.Pool({connectionString: url.href});
  try {
    const existing = await pool.query("SELECT tablename FROM pg_tables WHERE schemaname='public'");
    assert.equal(existing.rows.length, 0, 'Integration test requires an empty disposable database');
    await pool.query(`CREATE TABLE users(id BIGSERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE items(id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,value DOUBLE PRECISION NOT NULL,currency TEXT NOT NULL,condition TEXT,low DOUBLE PRECISION,high DOUBLE PRECISION,category TEXT,image_data TEXT,notes TEXT,saved_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      INSERT INTO users(email,password_hash) VALUES('legacy@example.test','unused');
      INSERT INTO items(user_id,name,value,currency) VALUES(1,'Legacy item',25,'USD');`);
    const env = {NODE_ENV:'test', SESSION_SECRET:'integration-test-secret-only'};
    const first = createApp({database:pool, env});
    await first.initDatabase();
    await first.initDatabase();
    assert.equal((await pool.query('SELECT value FROM items WHERE id=1')).rows[0].value, 25);
    assert.equal((await pool.query('SELECT auth_version FROM users WHERE id=1')).rows[0].auth_version, 0);
    const signup = await request(first.app).post('/api/auth/register').send({email:'integration@example.test',password:'test password'}).expect(200);
    const cookie = signup.headers['set-cookie'][0].split(';')[0];
    const second = createApp({database:pool, env});
    const me = await request(second.app).get('/api/auth/me').set('Cookie',cookie).expect(200);
    assert.equal(me.body.user.email, 'integration@example.test');
    await request(second.app).post('/api/items').set('Cookie',cookie).send({name:'Unknown value',value:null,currency:'NOK'}).expect(200);
    assert.equal((await pool.query("SELECT value FROM items WHERE name='Unknown value'")).rows[0].value, null);
    const attempts = await Promise.all(Array.from({length:30},()=>pool.query(`INSERT INTO api_usage(key,window_key,count) VALUES($1,$2,1)
      ON CONFLICT(key,window_key) DO UPDATE SET count=LEAST(api_usage.count+1,$3) RETURNING count`,['test:quota','2099-01-01',21])));
    assert.equal(attempts.filter(r=>r.rows[0].count<=20).length,20);
    await request(second.app).post('/api/auth/password').set('Cookie',cookie).send({password:'test password',newPassword:'replacement password'}).expect(200);
    await request(first.app).get('/api/items').set('Cookie',cookie).expect(401);
  } finally {
    await pool.end();
  }
});
