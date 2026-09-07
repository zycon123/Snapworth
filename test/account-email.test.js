import { test } from 'node:test';
import assert from 'node:assert/strict';
import { newDb } from 'pg-mem';
import session from 'express-session';
import request from 'supertest';
import { createApp } from '../server.js';
import { emailConfiguration, emailTransport } from '../account-email.js';

async function fixture(){
 const db=newDb();const {Pool}=db.adapters.createPg();const pool=new Pool();const mail=[];
 const instance=createApp({database:pool,sessionStore:new session.MemoryStore(),env:{NODE_ENV:'test',SESSION_SECRET:'test-secret',EMAIL_VERIFICATION_REQUIRED:'true',PUBLIC_ORIGIN:'https://snapworth.example'},sendMail:async message=>mail.push(message)});
 await instance.initDatabase();return {...instance,pool,mail};
}
const credentials={email:'person@example.test',password:'original password'};
function link(mail){const url=new URL(mail.text.match(/https:\/\/\S+/)[0]);return Object.fromEntries(new URLSearchParams(url.hash.slice(1)));}

test('verification required: no session before confirmation; hashed expiring links are single-use',async()=>{
 const {app,pool,mail}=await fixture();const agent=request.agent(app);
 await agent.post('/api/auth/register').send(credentials).expect(200);
 assert.equal((await agent.get('/api/auth/me')).body.user,null);
 await agent.post('/api/auth/login').send(credentials).expect(403);
 assert.equal(mail.length,1);const token=link(mail[0]);
 const row=(await pool.query('SELECT token_hash FROM account_tokens')).rows[0];assert.notEqual(row.token_hash,token.token);
 await agent.post('/api/auth/complete-email').send(token).expect(200);
 await agent.post('/api/auth/complete-email').send(token).expect(400);
 await agent.post('/api/auth/login').send(credentials).expect(200);
 await agent.get('/api/items').expect(200);
});

test('password recovery revokes old sessions and old password, without exposing account existence',async()=>{
 const {app,pool,mail}=await fixture();const agent=request.agent(app);
 await agent.post('/api/auth/register').send(credentials).expect(200);
 await agent.post('/api/auth/complete-email').send(link(mail[0])).expect(200);
 await agent.post('/api/auth/login').send(credentials).expect(200);
 await pool.query('DELETE FROM api_usage'); // advance the fixture past the email cooldown
 const known=await request(app).post('/api/auth/forgot-password').send({email:credentials.email}).expect(200);
 const absent=await request(app).post('/api/auth/forgot-password').send({email:'absent@example.test'}).expect(200);
 assert.deepEqual(known.body,absent.body);assert.equal(mail.length,2);
 const token=link(mail[1]);
 await request(app).post('/api/auth/complete-email').send({...token,password:'new secure password'}).expect(200);
 await agent.get('/api/items').expect(401);
 await request(app).post('/api/auth/login').send(credentials).expect(401);
 await request(app).post('/api/auth/login').send({...credentials,password:'new secure password'}).expect(200);
 await request(app).post('/api/auth/complete-email').send({...token,password:'other password'}).expect(400);
});

test('expired or wrong-purpose links fail, and resend cooldown prevents duplicate sends',async()=>{
 const {app,pool,mail}=await fixture();
 await request(app).post('/api/auth/register').send(credentials).expect(200);
 await request(app).post('/api/auth/resend-verification').send({email:credentials.email}).expect(200);
 assert.equal(mail.length,1);const token=link(mail[0]);
 await request(app).post('/api/auth/complete-email').send({...token,purpose:'reset',password:'replacement password'}).expect(400);
 await pool.query('UPDATE account_tokens SET expires_at=$1',[new Date('2000-01-01')]);
 await request(app).post('/api/auth/complete-email').send(token).expect(400);
 await request(app).post('/api/auth/login').send(credentials).expect(403);
});

test('email configuration requires an exact HTTPS origin and sender',()=>{
 assert.equal(emailConfiguration({}),false);
 assert.equal(emailConfiguration({PUBLIC_ORIGIN:'https://app.example',EMAIL_FROM:'accounts@example.com',RESEND_API_KEY:'test-only'}),true);
 assert.equal(emailConfiguration({PUBLIC_ORIGIN:'https://app.example/extra',EMAIL_FROM:'accounts@example.com',RESEND_API_KEY:'test-only'}),false);
});

test('Brevo transport uses its API contract and Proton reply address without falling back to Resend',async()=>{
 const env={PUBLIC_ORIGIN:'https://app.example',EMAIL_PROVIDER:'brevo',EMAIL_FROM:'zyconstudios@protonmail.com',BREVO_API_KEY:'test-only'};
 assert.equal(emailConfiguration(env),true);
 assert.equal(emailConfiguration({...env,BREVO_API_KEY:'',RESEND_API_KEY:'test-only'}),false);
 assert.equal(emailConfiguration({...env,EMAIL_PROVIDER:'unknown'}),false);
 const calls=[];
 const send=emailTransport(env,async(url,options)=>{calls.push({url,options});return new Response(JSON.stringify({messageId:'test-message'}),{status:201})});
 await send({to:'recipient@example.test',subject:'Confirm account',text:'Link with fragment'});
 assert.equal(calls[0].url,'https://api.brevo.com/v3/smtp/email');
 assert.equal(calls[0].options.headers['api-key'],'test-only');
 const body=JSON.parse(calls[0].options.body);
 assert.deepEqual(body.to,[{email:'recipient@example.test'}]);
 assert.equal(body.replyTo.email,env.EMAIL_FROM);assert.equal(body.textContent,'Link with fragment');
 await assert.rejects(emailTransport(env,async()=>new Response('{}'))({to:'recipient@example.test'}),/unavailable/);
});
