import { test } from 'node:test';
import assert from 'node:assert/strict';
import { newDb } from 'pg-mem';
import session from 'express-session';
import request from 'supertest';
import sharp from 'sharp';
import { createApp } from '../server.js';
import { databaseOptions,validateEnvironment,normalizeImage,storedImage,identification,fetchJson,itemInput } from '../security.js';
import { comparableItems,relevantListing,robustValuation } from '../pricing.js';

const valid={item_name:'Pokemon Mew plush',brand:null,model:null,category:'Toys',confidence:.8,search_query:'Pokemon Mew plush',notes:'Photo evidence',needs_more_photos:false};
const response=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
const ai=()=>response({status:'completed',output:[{content:[{type:'output_text',text:JSON.stringify(valid)}]}]});
const png=()=>sharp({create:{width:8,height:8,channels:3,background:'pink'}}).png().toBuffer();
async function fixture(options={}){
 const db=newDb();const {Pool}=db.adapters.createPg();const pool=new Pool();
 const instance=createApp({database:pool,sessionStore:new session.MemoryStore(),env:{NODE_ENV:'test',SESSION_SECRET:'test-session-secret',OPENAI_API_KEY:'test-only',EBAY_CLIENT_ID:'test',EBAY_CLIENT_SECRET:'test'},fetcher:async()=>ai(),...options});
 await instance.initDatabase();
 return {...instance,db};
}
async function user(app,email='a@example.test'){
 const agent=request.agent(app);
 const result=await agent.post('/api/auth/register').send({email,password:'test password'}).expect(200);
 return {agent,id:result.body.user.id,cookie:result.headers['set-cookie'][0].split(';')[0]};
}
test('production requires a strong session secret and verifies DB TLS even with URL overrides',()=>{
 assert.throws(()=>validateEnvironment({NODE_ENV:'production'}));
 assert.throws(()=>validateEnvironment({NODE_ENV:'production',SESSION_SECRET:'change-me'.repeat(8)}));
 validateEnvironment({NODE_ENV:'production',SESSION_SECRET:'e17470aad62648bca73153b7b4f89d8a'});
 const config=databaseOptions({NODE_ENV:'production',DATABASE_URL:'postgres://user:password@localhost/db?sslmode=no-verify',DATABASE_CA_CERT:'certificate\\nline'});
 assert.equal(config.ssl.rejectUnauthorized,true);assert(!config.connectionString.includes('sslmode'));assert.equal(config.ssl.ca,'certificate\nline');
});
test('decoder rejects corrupt, mismatched and oversized images; stored data is validated',async()=>{
 const bytes=await png();
 const output=await normalizeImage(bytes,'image/png');assert.equal((await sharp(output).metadata()).format,'jpeg');
 await assert.rejects(normalizeImage(bytes,'image/jpeg'));
 await assert.rejects(normalizeImage(Buffer.from('not an image'),'image/png'));
 await assert.rejects(normalizeImage(bytes,'image/svg+xml'));
 await assert.rejects(normalizeImage(Buffer.alloc(8*1024*1024+1),'image/png'),e=>e.status===413);
 const huge=await sharp({create:{width:5000,height:5000,channels:3,background:'white'}}).png().toBuffer();
 await assert.rejects(normalizeImage(huge,'image/png'));
 await assert.rejects(storedImage('data:image/garbage,not-base64'));
 await assert.rejects(storedImage('data:image/png;base64,AA'));
 assert.match(await storedImage('data:image/png;base64,'+bytes.toString('base64')),/^data:image\/jpeg;base64,/);
});
test('inventory accepts unknown prices but rejects negative, malformed and invalid currency',()=>{
 for(const value of [-1,0,Infinity,true,{},10000001])assert.throws(()=>itemInput({name:'Chair',value,currency:'NOK'}));
 assert.equal(itemInput({name:'Chair',value:null,currency:'NOK'}).value,null);
 assert.throws(()=>itemInput({name:'Chair',value:20,currency:'XXX'}));
 assert.throws(()=>itemInput({name:'Chair',value:20,currency:'NOK',low:40,high:20}));
});
test('matching rejects accessories, broad names, wrong regions and mixed currencies',()=>{
 for(const [q,title] of [['Pokemon card','Pokemon card storage album'],['Nintendo GameCube','Nintendo GameCube controller'],['PlayStation game','PlayStation game display stand'],['Pokemon Mew plush','Pokemon Mew plush keychain'],['iPhone 13 phone','iPhone 13 phone cover']])assert.equal(relevantListing(title,q,'EBAY_US'),false,title);
 for(const q of ['Pokemon Mew plush','Pokemon card','Nintendo GameCube console','PlayStation game','Apple iPhone 13 phone','Makita drill','IKEA chair'])assert.equal(relevantListing(q,q,'EBAY_US'),true,q);
 assert.equal(relevantListing('Nintendo GameCube console PAL','Nintendo GameCube console','EBAY_US'),false);
 assert.equal(relevantListing('Mew pink toy','Mew','EBAY_US'),false);
 const items=[10,11,12].map((v,i)=>({itemId:String(i),title:'Pokemon Mew plush',price:{value:String(v),currency:i===0?'EUR':'USD'}}));
 assert.equal(comparableItems(items,'Pokemon Mew plush','EBAY_US','USD').length,2);
 assert.equal(comparableItems([...items,...items],'Pokemon Mew plush','EBAY_US','USD').length,2);
 assert.equal(robustValuation([10,11,12],.94).valuation.fair,10.34);
});
test('anonymous callers cannot reach AI, pricing or inventory; cross-site writes rejected',async()=>{
 let calls=0;const {app}=await fixture({fetcher:async()=>{calls++;return ai()}});
 await request(app).post('/api/identify').attach('image',await png(),'a.png').expect(401);
 await request(app).get('/api/comps?q=Pokemon+card&market=EBAY_US').expect(401);
 await request(app).get('/api/items').expect(401);assert.equal(calls,0);
 await request(app).post('/api/auth/register').set('Origin','https://evil.example').send({email:'b@example.test',password:'password'}).expect(403);
});
test('real HTTP + SQL: owner isolation, unknown-price persistence, images, logout invalidation',async()=>{
 const {app}=await fixture();const a=await user(app),b=await user(app,'b@example.test');
 const saved=await a.agent.post('/api/items').send({name:'Chair',value:null,currency:'NOK',user_id:b.id,image:'data:image/png;base64,'+(await png()).toString('base64')}).expect(200);
 const id=saved.body.item.id;assert.equal(String(saved.body.item.user_id),String(a.id));assert.equal(saved.body.item.value,null);
 const list=await a.agent.get('/api/items').expect(200);assert.equal(list.body.items.length,1);assert(!('image_data' in list.body.items[0]));
 assert.equal((await b.agent.get('/api/items')).body.items.length,0);
 for(const method of ['get','patch','delete'])await b.agent[method]('/api/items/'+id).send(method==='patch'?{notes:'stolen'}:undefined).expect(404);
 await b.agent.get('/api/items/'+id+'/image').expect(404);
 await a.agent.get('/api/items/'+id+'/image').expect(200).expect('Content-Type',/image\/jpeg/);
 await a.agent.patch('/api/items/'+id).send({notes:'kept',condition:'Good',user_id:b.id}).expect(200);
 assert.equal((await a.agent.get('/api/items/'+id)).body.item.notes,'kept');
 const logout=await a.agent.post('/api/auth/logout').expect(200);assert.match(logout.headers['set-cookie'][0],/Expires=Thu, 01 Jan 1970/);
 await request(app).get('/api/items').set('Cookie',a.cookie).expect(401);
});
test('login regenerates the session and invalidates previous session ID',async()=>{
 const {app}=await fixture();const a=await user(app);
 const login=await a.agent.post('/api/auth/login').send({email:'a@example.test',password:'test password'}).expect(200);
 assert.notEqual(login.headers['set-cookie'][0].split(';')[0],a.cookie);
 await request(app).get('/api/items').set('Cookie',a.cookie).expect(401);
});
test('real multipart checks and daily quotas stop rejected requests before upstream calls',async()=>{
 let calls=0;const {app}=await fixture({aiDailyLimit:3,fetcher:async()=>{calls++;return ai()}});const {agent}=await user(app);
 await agent.post('/api/identify').attach('image',Buffer.from('fake'),{filename:'a.png',contentType:'image/png'}).expect(400);
 await agent.post('/api/identify').attach('image',await png(),'a.png').expect(200);
 await agent.post('/api/identify').attach('image',await png(),'a.png').attach('extra',await png(),'b.png').expect(400);
 await agent.post('/api/identify').attach('image',await png(),'a.png').expect(429);assert.equal(calls,1);
});
test('upstream malformed JSON, timeout and error details are handled safely',async()=>{
 assert.throws(()=>identification({output:[{content:[{text:'{"confidence":42}'}]}]}));
 await assert.rejects(fetchJson(async()=>new Response('bad'),'https://mock'),e=>e.status===502);
 await assert.rejects(fetchJson(async()=>response({error:'SECRET'},401),'https://mock'),e=>e.status===502&&!e.message.includes('SECRET'));
 await assert.rejects(fetchJson((url,{signal})=>new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('abort')))),'https://mock',{},10),e=>e.status===504);
 const {app}=await fixture({fetcher:async()=>response({error:'SECRET_PROVIDER_MESSAGE'},401)});const {agent}=await user(app);
 const result=await agent.post('/api/identify').attach('image',await png(),'a.png').expect(502);assert(!result.text.includes('SECRET'));
});
test('eBay refreshes one expired token, caches replacement, and never prices mixed-currency samples',async()=>{
 let tokens=0,searches=0;
 const {app}=await fixture({fetcher:async(url)=>{
  if(String(url).includes('oauth2'))return response({access_token:'token'+(++tokens),expires_in:7200});
  if(++searches===1)return response({},401);
  return response({itemSummaries:[10,11,12].map((price,i)=>({itemId:String(i),title:'Pokemon Mew plush',price:{value:String(price),currency:'USD'}}))});
 }});const {agent}=await user(app);
 for(let i=0;i<2;i++){const r=await agent.get('/api/comps?q=Pokemon+Mew+plush&market=EBAY_US').expect(200);assert.equal(r.body.currency,'USD')}
 assert.equal(tokens,2);assert.equal(searches,3);
 await agent.get('/api/comps?q=brukt+stol&market=NORWAY').expect(503);
});
test('database failure gives a sanitized API error and an unhealthy readiness response',async()=>{
 const {app,pool}=await fixture();const {agent}=await user(app);
 pool.query=async()=>{throw new Error('DATABASE_SECRET')};
 const r=await agent.get('/api/items').expect(503);assert(!r.text.includes('SECRET'));
 await request(app).get('/health').expect(503);
});
test('password changes revoke other sessions and account deletion removes owned items',async()=>{
 const {app}=await fixture();const a=await user(app),b=await user(app,'b@example.test');
 const other=request.agent(app);await other.post('/api/auth/login').send({email:'a@example.test',password:'test password'}).expect(200);
 await a.agent.post('/api/items').send({name:'Chair',value:500,currency:'NOK'}).expect(200);
 await b.agent.post('/api/items').send({name:'Watch',value:50,currency:'USD'}).expect(200);
 await a.agent.post('/api/auth/password').send({password:'wrong',newPassword:'next password'}).expect(401);
 await a.agent.post('/api/auth/password').send({password:'test password',newPassword:'next password'}).expect(200);
 await other.get('/api/items').expect(401);
 assert.equal((await other.get('/api/auth/me')).body.user,null);
 await a.agent.delete('/api/auth/account').send({password:'wrong'}).expect(401);
 await a.agent.delete('/api/auth/account').send({password:'next password'}).expect(200);
 await a.agent.get('/api/items').expect(401);
 assert.equal((await b.agent.get('/api/items')).body.items.length,1);
});
test('pagination preserves all legacy items without sending all photos',async()=>{
 const {app,pool}=await fixture();const {agent,id}=await user(app);
 for(let i=0;i<105;i++)await pool.query('INSERT INTO items(user_id,name,value,currency) VALUES($1,$2,$3,$4)',[id,'Legacy '+i,i===0?0:100,'NOK']);
 const first=await agent.get('/api/items').expect(200);
 assert.equal(first.body.items.length,100);assert(first.body.nextCursor);
 const second=await agent.get('/api/items?before='+first.body.nextCursor).expect(200);
 assert.equal(second.body.items.length,5);assert.equal(second.body.nextCursor,null);
 assert.equal(new Set([...first.body.items,...second.body.items].map(x=>x.id)).size,105);
});
test('concurrent expensive requests are bounded and capacity recovers',async()=>{
 let release;const gate=new Promise(resolve=>release=resolve);let calls=0;
 const {app}=await fixture({fetcher:async()=>{calls++;await gate;return ai()}});const {agent}=await user(app);const image=await png();
 const requests=Array.from({length:4},()=>agent.post('/api/identify').attach('image',image,'a.png').then(r=>r));
 for(let i=0;i<100&&calls<4;i++)await new Promise(resolve=>setTimeout(resolve,5));
 assert.equal(calls,4);
 await agent.post('/api/identify').attach('image',image,'a.png').expect(503);
 release();for(const result of await Promise.all(requests))assert.equal(result.status,200);
 await agent.post('/api/identify').attach('image',image,'a.png').expect(200);
});
