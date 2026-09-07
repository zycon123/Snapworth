import express from "express";
import multer from "multer";
import dotenv from "dotenv";
import session from "express-session";
import bcrypt from "bcryptjs";
import pg from "pg";
import connectPgSimple from "connect-pg-simple";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

import { fileURLToPath } from 'node:url';
import { validateEnvironment, validatePublicSignup, databaseOptions, PublicError, text, itemInput, storedImage, normalizeImage, identification, fetchJson } from './security.js';
import { comparableItems, robustValuation } from './pricing.js';
import { identificationPrompt } from './identification-prompt.js';
import { accountEmail } from './account-email.js';

export function createApp({env=process.env, database, sessionStore, fetcher=globalThis.fetch, sendMail, upstreamTimeout=20000, aiDailyLimit=20, searchDailyLimit=100}={}) {
validateEnvironment(env);
validatePublicSignup(env);
const pool=database || new pg.Pool(databaseOptions(env));
pool.on?.('error',()=>console.error('Database connection unavailable'));
const app=express();
if (env.NODE_ENV==="production") app.set("trust proxy",1);

app.use(helmet({
  contentSecurityPolicy:{
    directives:{
      defaultSrc:["'self'"],
      imgSrc:["'self'","data:","blob:"],
      styleSrc:["'self'","'unsafe-inline'"],
      scriptSrc:["'self'","'unsafe-inline'"],
      connectSrc:["'self'"],
          frameAncestors:["'none'"]
    }
   }
}));




const PgSession=connectPgSimple(session);

app.use(session({
  store:sessionStore || new PgSession({
    pool,
    createTableIfMissing:true
  }),
  secret:env.SESSION_SECRET || "development-only-change-me",
  resave:false,
  saveUninitialized:false,
  cookie:{
    httpOnly:true,
    sameSite:"lax",
    secure:env.NODE_ENV==="production",
    maxAge:1000*60*60*24*30
 }
}));

const authLimiter=rateLimit({windowMs:15*60*1000,limit:20,standardHeaders:"draft-7",legacyHeaders:false,message:{error:'Too many sign-in attempts. Try again in 15 minutes.'}});
const apiLimiter=rateLimit({windowMs:60*1000,limit:120,standardHeaders:"draft-7",legacyHeaders:false,message:{error:'Too many requests. Please wait a minute.'}});
app.use('/api', (req,res,next)=>{res.set('Cache-Control','no-store');next()});
app.use('/api', apiLimiter);
app.use('/api', (req,res,next)=>{
  if (!['GET','HEAD','OPTIONS'].includes(req.method)) {
    const origin=req.get('origin');
    const expected=env.PUBLIC_ORIGIN || req.protocol+'://'+req.get('host');
    if (req.get('sec-fetch-site')==='cross-site' || (origin && origin!==expected)) return res.status(403).json({error:'Cross-site request rejected.'});
  }
  next();
});
app.use(express.json({limit:'1.5mb'}));
const identifyIpLimiter=rateLimit({windowMs:60000,limit:10,standardHeaders:'draft-7',legacyHeaders:false,message:{error:'Too many scans. Please wait a minute.'}});
function budget(kind,limit,globalLimit){return async(req,res,next)=>{
  const windowKey=new Date().toISOString().slice(0,10);
  for(const [key,max] of [[kind+':user:'+req.session.userId,limit],[kind+':global',globalLimit]]){
    const result=await pool.query(`INSERT INTO api_usage(key,window_key,count) VALUES($1,$2,1)
      ON CONFLICT(key,window_key) DO UPDATE SET count=LEAST(api_usage.count+1,$3) RETURNING count`,[key,windowKey,max+1]);
    if(!result.rows.length || Number(result.rows[0].count)>max)return res.status(429).json({error:'Daily service allowance reached. Please try again tomorrow.'});
  }
  next();
}}
let active=0;
function capacity(req,res,next){
  if(active>=4)return res.status(503).json({error:'The service is busy. Please try again shortly.'});
  active++;let released=false;
  const release=()=>{if(!released){released=true;active--}};
  req.releaseCapacity=release;
  res.once('finish',release);res.once('close',()=>{if(!req.processing)release()});next();
}
const saveLimiter=rateLimit({windowMs:60000,limit:20,standardHeaders:'draft-7',legacyHeaders:false,message:{error:'Too many changes. Please wait a minute.'}});
async function signIn(req,userId){
  await new Promise((resolve,reject)=>req.session.regenerate(e=>e?reject(e):resolve()));
  const user=await pool.query('SELECT auth_version FROM users WHERE id=$1',[userId]);
  req.session.userId=String(userId);
  req.session.authVersion=user.rows[0].auth_version;
  await new Promise((resolve,reject)=>req.session.save(e=>e?reject(e):resolve()));
}
const cookieOptions={path:'/',httpOnly:true,sameSite:'lax',secure:env.NODE_ENV==='production'};
const emailAccounts=accountEmail({app,pool,env,limiter:authLimiter,sendMail,fetcher});


async function initDatabase(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      auth_version INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS items(
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      value DOUBLE PRECISION,
      currency TEXT NOT NULL,
      condition TEXT,
      low DOUBLE PRECISION,
      high DOUBLE PRECISION,
      category TEXT,
      image_data TEXT,
      notes TEXT,
      saved_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE items ALTER COLUMN value DROP NOT NULL;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_version INTEGER NOT NULL DEFAULT 0;
    CREATE INDEX IF NOT EXISTS items_user_id_id_idx ON items(user_id,id DESC);
    CREATE TABLE IF NOT EXISTS api_usage(key TEXT NOT NULL,window_key TEXT NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(key,window_key));

  `);
  await pool.query('DELETE FROM api_usage WHERE window_key < $1',[new Date(Date.now()-2*86400000).toISOString().slice(0,10)]);
  await emailAccounts.init();
}

async function auth(req,res,next){
 if(!req.session.userId)return res.status(401).json({error:'Sign in required.'});
 const user=await pool.query('SELECT id,auth_version,email_verified FROM users WHERE id=$1',[req.session.userId]);
 if(!user.rows.length || user.rows[0].auth_version !== (req.session.authVersion||0))return res.status(401).json({error:'Sign in required.'});
 if(emailAccounts.enabled&&!user.rows[0].email_verified)return res.status(403).json({error:'Confirm your email address before continuing.'});
 next();
}
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:8*1024*1024,files:1,fields:0,parts:2},
 fileFilter(req,file,cb){cb(['image/jpeg','image/png','image/webp'].includes(file.mimetype)?null:new PublicError(415,'Use a JPEG, PNG or WebP image.'),true)}});
app.get('/health',async(req,res)=>{
 try{await pool.query('SELECT 1');res.json({ok:true,service:'snapworth',version:'1.0.0'})}
 catch{res.status(503).json({ok:false})}
});
app.get('/api/site-info',(req,res)=>res.json({operator:env.SITE_OPERATOR||null,supportEmail:env.SUPPORT_EMAIL||null}));

app.use(express.static(fileURLToPath(new URL('./public',import.meta.url))));

app.post("/api/auth/register",authLimiter,async(req,res)=>{
 try{
  if(env.NODE_ENV==='production' && env.PUBLIC_SIGNUP_ENABLED!=='true')throw new PublicError(503,'Public registration is not open yet.');
  const email=text(req.body?.email,254,true).toLowerCase();
  const password=req.body?.password;
  if(typeof password!=='string' || Buffer.byteLength(password,'utf8')>72)throw new PublicError(400,'Password must be at most 72 UTF-8 bytes.');

  if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)){
   return res.status(400).json({error:"Enter a valid email."});
  }

  if(password.length<8){
   return res.status(400).json({error:"Password must be at least 8 characters."});
  }

  const hash=await bcrypt.hash(password,12);

  const result=await pool.query(
   `INSERT INTO users(email,password_hash)
    VALUES($1,$2)
    RETURNING id,email`,
   [email,hash]
  );

  const user=result.rows[0];

  if(emailAccounts.enabled){await emailAccounts.issue(user,'verify');return res.json({...emailAccounts.generic,verificationRequired:true});}

  await signIn(req,user.id);

  res.json({
   user:{
    id:user.id,
    email:user.email
   }
  });

 }catch(e){
  if(e instanceof PublicError)return res.status(e.status).json({error:e.message});
  if(e.code==="23505"){
   if(emailAccounts.enabled)return res.json({...emailAccounts.generic,verificationRequired:true});
   return res.status(409).json({error:"Account already exists."});
  }

  console.error("Register error:");
  res.status(500).json({error:"Could not create account."});
 }
});

app.post("/api/auth/login",authLimiter,async(req,res)=>{
 try{
  const email=text(req.body?.email,254,true).toLowerCase();
  const password=req.body?.password;
  if(typeof password!=='string')throw new PublicError(400,'Enter your password.'); // Preserve legacy bcrypt password semantics at login.

  const result=await pool.query(
   "SELECT id,email,password_hash,email_verified FROM users WHERE email=$1",
   [email]
  );

  const u=result.rows[0];

  if(!u || !(await bcrypt.compare(password,u.password_hash))){
   return res.status(401).json({error:"Invalid email or password."});
  }

  if(emailAccounts.enabled&&!u.email_verified)return res.status(403).json({error:'Confirm your email first. Use Resend confirmation if you need a new link.'});

  await signIn(req,u.id);

  res.json({
   user:{
    id:u.id,
    email:u.email
   }
  });

 }catch(e){
  if(e instanceof PublicError)return res.status(e.status).json({error:e.message});
  console.error("Login error:");
  res.status(500).json({error:"Could not sign in."});
 }
});

app.post("/api/auth/logout",(req,res)=>{
 req.session.destroy((error)=>{
  if(error)return res.status(503).json({error:"Could not sign out. Please try again."});
  res.clearCookie("connect.sid",cookieOptions);
  res.json({ok:true});
 });
});


app.post('/api/auth/password',auth,authLimiter,async(req,res)=>{
 const password=req.body?.password,newPassword=req.body?.newPassword;
 if(typeof password!=='string'||typeof newPassword!=='string'||newPassword.length<8||Buffer.byteLength(newPassword)>72)throw new PublicError(400,'Use a password of at least 8 characters and at most 72 UTF-8 bytes.');
 const result=await pool.query('SELECT password_hash FROM users WHERE id=$1',[req.session.userId]);
 if(!result.rows[0]||!await bcrypt.compare(password,result.rows[0].password_hash))throw new PublicError(401,'Current password is incorrect.');
 const hash=await bcrypt.hash(newPassword,12),userId=req.session.userId;
 await pool.query('UPDATE users SET password_hash=$1,auth_version=auth_version+1 WHERE id=$2',[hash,userId]);
 await signIn(req,userId);
 res.json({ok:true});
});
app.delete('/api/auth/account',auth,authLimiter,async(req,res)=>{
 const password=req.body?.password;
 if(typeof password!=='string')throw new PublicError(400,'Enter your current password.');
 const result=await pool.query('SELECT password_hash FROM users WHERE id=$1',[req.session.userId]);
 if(!result.rows[0]||!await bcrypt.compare(password,result.rows[0].password_hash))throw new PublicError(401,'Current password is incorrect.');
 await pool.query('DELETE FROM users WHERE id=$1',[req.session.userId]);
 // All other sessions immediately lose access because auth checks account existence.
 req.session.destroy(()=>{res.clearCookie('connect.sid',cookieOptions);res.json({ok:true})});
});

app.get("/api/auth/me",async(req,res)=>{
 try{
  if(!req.session.userId){
   return res.json({user:null});
  }

  const result=await pool.query(
   "SELECT id,email,auth_version,email_verified FROM users WHERE id=$1",
   [req.session.userId]
  );

  res.json({
   user:result.rows[0] && (!emailAccounts.enabled||result.rows[0].email_verified) && result.rows[0].auth_version === (req.session.authVersion||0) ? {id:result.rows[0].id,email:result.rows[0].email} : null
  });

 }catch(e){
  if(e instanceof PublicError)return res.status(e.status).json({error:e.message});
  console.error("Auth check error:");
  res.status(500).json({error:"Could not check account."});
 }
});



app.get("/api/items",auth,async(req,res)=>{
 try{
  const result=await pool.query(
   `SELECT id,name,value,currency,condition,low,high,category,notes,saved_at,
    (image_data IS NOT NULL) AS has_image FROM items WHERE user_id=$1 AND id<$2 ORDER BY id DESC LIMIT 101`,
   [req.session.userId, /^\d{1,19}$/.test(String(req.query.before||'')) ? req.query.before : '9223372036854775807']
  );

  const rows=result.rows.slice(0,100);
  res.json({items:rows,nextCursor:result.rows.length>100?String(rows.at(-1).id):null});

 }catch(e){
  if(e instanceof PublicError)return res.status(e.status).json({error:e.message});
  console.error("Load items error:");
  res.status(500).json({error:"Could not load items."});
 }
});




app.post("/api/items",auth,saveLimiter,capacity,async(req,res)=>{
 req.processing=true;
 try{
  const x=itemInput(req.body);
  const imageData=await storedImage(req.body.image);
  const notes=x.notes;
  const result=await pool.query(
   `INSERT INTO items(
     user_id,
     name,
     value,
     currency,
     condition,
     low,
     high,
     category,
     image_data,
     notes
    )
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    RETURNING *`,
   [
    req.session.userId,
    String(x.name),
    x.value,
    String(x.currency),
    String(x.condition||""),
    x.low,
    x.high,
    String(x.category||""),
    imageData,
    notes
   ]
  );

  res.json({item:result.rows[0]});

 }catch(e){
  if(e instanceof PublicError)return res.status(e.status).json({error:e.message});
  console.error("Save item error:");
  res.status(500).json({error:"Could not save item."});
 }finally{req.releaseCapacity()}
});

app.get('/api/items/:id/image',auth,capacity,async(req,res)=>{
 req.processing=true;
 try{
   const result=await pool.query('SELECT image_data FROM items WHERE id=$1 AND user_id=$2',[req.params.id,req.session.userId]);
   if(!result.rows[0]?.image_data)return res.sendStatus(404);
   const image=await storedImage(result.rows[0].image_data);
   res.type('image/jpeg').send(Buffer.from(image.split(',')[1],'base64'));
 }finally{req.releaseCapacity()}
});

app.get("/api/items/:id",auth,async(req,res)=>{
 try{
  const result=await pool.query(
   "SELECT * FROM items WHERE id=$1 AND user_id=$2",
   [req.params.id,req.session.userId]
  );

  const item=result.rows[0];

  if(!item){
   return res.status(404).json({error:"Item not found."});
  }

  res.json({item});

 }catch(e){
  if(e instanceof PublicError)return res.status(e.status).json({error:e.message});
  console.error("Load item error:");
  res.status(500).json({error:"Could not load item."});
 }
});

app.patch("/api/items/:id",auth,async(req,res)=>{
 try{
  const x=req.body||{};

  const currentResult=await pool.query(
   "SELECT * FROM items WHERE id=$1 AND user_id=$2",
   [req.params.id,req.session.userId]
  );

  const current=currentResult.rows[0];

  if(!current){
   return res.status(404).json({error:"Item not found."});
  }

  const notes=String(
   x.notes ?? current.notes ?? ""
  ).slice(0,2000);

  const condition=text(x.condition ?? current.condition ?? "",80);

  const result=await pool.query(
   `UPDATE items
    SET notes=$1, condition=$2
    WHERE id=$3 AND user_id=$4
    RETURNING *`,
   [
    notes,
    condition,
    req.params.id,
    req.session.userId
   ]
  );

  res.json({item:result.rows[0]});

 }catch(e){
  if(e instanceof PublicError)return res.status(e.status).json({error:e.message});
  console.error("Update item error:");
  res.status(500).json({error:"Could not update item."});
 }
});

app.delete("/api/items/:id",auth,async(req,res)=>{
 try{
  const result=await pool.query(
   "DELETE FROM items WHERE id=$1 AND user_id=$2 RETURNING id",
   [req.params.id,req.session.userId]
  );

  if(!result.rows[0]){
   return res.status(404).json({error:"Item not found."});
  }

  res.json({ok:true});

 }catch(e){
  if(e instanceof PublicError)return res.status(e.status).json({error:e.message});
  console.error("Delete item error:");
  res.status(500).json({error:"Could not delete item."});
 }
});


app.post('/api/identify',auth,identifyIpLimiter,capacity,budget('identify',aiDailyLimit,500),upload.single('image'),async(req,res)=>{
 req.processing=true;
 try{
 if(!env.OPENAI_API_KEY)throw new PublicError(503,'Image identification is not connected yet.');
 if(!req.file)throw new PublicError(400,'No image uploaded.');
 const bytes=await normalizeImage(req.file.buffer,req.file.mimetype);
 const payload=await fetchJson(fetcher,'https://api.openai.com/v1/responses',{method:'POST',headers:{Authorization:`Bearer ${env.OPENAI_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({
   model:env.OPENAI_MODEL||'gpt-5.6-luna',store:false,
   input:[{role:'user',content:[{type:'input_text',text:identificationPrompt},{type:'input_image',image_url:'data:image/jpeg;base64,'+bytes.toString('base64')}]}]
 })},upstreamTimeout);
 res.json(identification(payload));
 }finally{req.releaseCapacity()}
});

const marketplaceMap={
 EBAY_US:{id:"EBAY_US",currency:"USD"},
 EBAY_GB:{id:"EBAY_GB",currency:"GBP"},
 EBAY_DE:{id:"EBAY_DE",currency:"EUR"}
};


let cachedToken=null,tokenUntil=0,tokenPending=null;
async function ebayToken(deadline=Date.now()+upstreamTimeout){
 if(cachedToken && Date.now()<tokenUntil)return cachedToken;
 if(tokenPending)return tokenPending;
 tokenPending=(async()=>{
   if(!env.EBAY_CLIENT_ID||!env.EBAY_CLIENT_SECRET)throw new PublicError(503,'Live pricing is not connected yet.');
   const basic=Buffer.from(`${env.EBAY_CLIENT_ID}:${env.EBAY_CLIENT_SECRET}`).toString('base64');
   const d=await fetchJson(fetcher,'https://api.ebay.com/identity/v1/oauth2/token',{method:'POST',headers:{Authorization:`Basic ${basic}`,'Content-Type':'application/x-www-form-urlencoded'},body:'grant_type=client_credentials&scope=https%3A%2F%2Fapi.ebay.com%2Foauth%2Fapi_scope'},Math.max(1,deadline-Date.now()));
   if(typeof d.access_token!=='string'||!d.access_token)throw new PublicError(502,'Live pricing is temporarily unavailable.');
   cachedToken=d.access_token;tokenUntil=Date.now()+Math.max(0,Math.min(Number(d.expires_in)||0,7200)-60)*1000;
   return cachedToken;
 })();
 try{return await tokenPending}finally{tokenPending=null}
}
app.get('/api/comps',auth,budget('comps',searchDailyLimit,2000),capacity,async(req,res)=>{
 req.processing=true;
 try{
 const q=text(req.query.q,240,true),requestedMarket=text(req.query.market||'NORWAY',20,true);
 if(requestedMarket==='NORWAY')return res.status(503).json({pricingUnavailable:true,source:'Norwegian market',currency:'NOK',market:'NORWAY',error:'Automatic Norwegian pricing is not connected. Compare current listings on FINN.no or Facebook Marketplace.'});
 const market=marketplaceMap[requestedMarket];
 if(!market)throw new PublicError(400,'Unsupported marketplace.');
 const condition=req.query.condition===undefined?1:Number(req.query.condition);
 if(!Number.isFinite(condition)||condition<.4||condition>1)throw new PublicError(400,'Invalid condition.');
 try{
   const url=new URL('https://api.ebay.com/buy/browse/v1/item_summary/search');
   url.searchParams.set('q',q);url.searchParams.set('limit','50');url.searchParams.set('filter','conditions:{USED},buyingOptions:{FIXED_PRICE}');
   let d;const deadline=Date.now()+upstreamTimeout;
   for(let attempt=0;attempt<2;attempt++){
     const token=await ebayToken(deadline);
     if(Date.now()>=deadline)throw new PublicError(504,'The request took too long. Please try again.');
     try{d=await fetchJson(fetcher,url,{headers:{Authorization:`Bearer ${token}`,'X-EBAY-C-MARKETPLACE-ID':market.id}},Math.max(1,deadline-Date.now()));break}
     catch(e){if(e.upstreamStatus!==401||attempt===1)throw e;cachedToken=null;tokenUntil=0}
   }
   const items=comparableItems(d.itemSummaries,q,market.id,market.currency);
   if(items.length<3)return res.status(422).json({pricingUnavailable:true,source:'eBay Browse API',error:'Not enough matching listings in the selected currency. Include the product type and exact model in your search.'});
   const v=robustValuation(items.map(x=>x.price),condition),clean=new Set(v.clean);
   res.json({demo:false,source:'eBay Browse API',currency:market.currency,count:v.clean.length,items:items.filter(x=>clean.has(x.price)),stats:v.stats,valuation:v.valuation});
 }catch(e){
  res.status(e.status||503).json({pricingUnavailable:true,source:'eBay Browse API',error:e instanceof PublicError?e.message:'Live pricing is temporarily unavailable.'})}
 }finally{req.releaseCapacity()}
});
app.use((error,req,res,next)=>{
 if(res.headersSent)return next(error);
 if(error instanceof PublicError)return res.status(error.status).json({error:error.message});
 if(error instanceof multer.MulterError)return res.status(error.code==='LIMIT_FILE_SIZE'?413:400).json({error:'Upload one JPEG, PNG or WebP image, at most 8 MB.'});
 if(error.type==='entity.too.large')return res.status(413).json({error:'Request is too large.'});
 if(error instanceof SyntaxError && 'body' in error)return res.status(400).json({error:'Invalid JSON request.'});
 console.error('Request failed',req.method,req.route?.path||'unknown');
 res.status(503).json({error:'Service temporarily unavailable. Please try again.'});
});
return {app,pool,initDatabase};
}

async function startServer(){
 dotenv.config();
 const {app,pool,initDatabase}=createApp();
 await initDatabase();
 const server=app.listen(process.env.PORT||3000,()=>console.log('SnapWorth started'));
 server.requestTimeout=30000;
 process.once('SIGTERM',()=>server.close(()=>pool.end()));
}
if(process.argv[1] && fileURLToPath(import.meta.url)===process.argv[1])startServer().catch(()=>{console.error('Startup failed. Check database and production configuration.');process.exitCode=1});
