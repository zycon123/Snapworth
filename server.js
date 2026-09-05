import express from "express";
import multer from "multer";
import dotenv from "dotenv";
import session from "express-session";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import connectSqlite3 from "connect-sqlite3";
dotenv.config();

const app=express();
if (process.env.NODE_ENV==="production") app.set("trust proxy",1);

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
app.use(express.json({limit:"1.5mb"}));

const SQLiteStore=connectSqlite3(session);
app.use(session({
  store:new SQLiteStore({db:"sessions.sqlite",dir:process.env.SESSION_DB_DIR||"."}),
  secret: process.env.SESSION_SECRET || "development-only-change-me",
  resave:false,
  saveUninitialized:false,
  cookie:{
    httpOnly:true,
    sameSite:"lax",
    secure:process.env.NODE_ENV==="production",
    maxAge:1000*60*60*24*30
  }
}));

const authLimiter=rateLimit({windowMs:15*60*1000,limit:20,standardHeaders:"draft-7",legacyHeaders:false});
const apiLimiter=rateLimit({windowMs:60*1000,limit:120,standardHeaders:"draft-7",legacyHeaders:false});
app.use("/api",apiLimiter);

const db=new Database(process.env.DB_PATH || "snapworth.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS items(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 name TEXT NOT NULL,
 value REAL NOT NULL,
 currency TEXT NOT NULL,
 condition TEXT,
 low REAL,
 high REAL,
 category TEXT,
 image_data TEXT,
 notes TEXT,
 saved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);`);
try { db.exec("ALTER TABLE items ADD COLUMN image_data TEXT"); } catch {}
try { db.exec("ALTER TABLE items ADD COLUMN notes TEXT"); } catch {}

function auth(req,res,next){
 if(!req.session.userId)return res.status(401).json({error:"Sign in required."});
 next();
}
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:8*1024*1024}});

const requiredProd=["SESSION_SECRET"];
if(process.env.NODE_ENV==="production"){
  const missing=requiredProd.filter(k=>!process.env[k] || process.env[k].includes("change"));
  if(missing.length) console.warn("WARNING: missing/weak production env:",missing.join(", "));
}
app.get("/health",(req,res)=>res.json({ok:true,service:"snapworth",version:"1.0.0"}));

app.use(express.static("public"));

function outputText(payload){
 return (payload.output||[]).flatMap(o=>o.content||[]).map(c=>c.text||"").join("").trim();
}


app.post("/api/auth/register",authLimiter,async(req,res)=>{
 try{
  const email=String(req.body.email||"").trim().toLowerCase();
  const password=String(req.body.password||"");
  if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))return res.status(400).json({error:"Enter a valid email."});
  if(password.length<8)return res.status(400).json({error:"Password must be at least 8 characters."});
  const hash=await bcrypt.hash(password,12);
  const info=db.prepare("INSERT INTO users(email,password_hash) VALUES(?,?)").run(email,hash);
  req.session.userId=Number(info.lastInsertRowid);
  res.json({user:{id:req.session.userId,email}});
 }catch(e){
  if(String(e.message).includes("UNIQUE"))return res.status(409).json({error:"Account already exists."});
  res.status(500).json({error:"Could not create account."});
 }
});
app.post("/api/auth/login",authLimiter,async(req,res)=>{
 const email=String(req.body.email||"").trim().toLowerCase(), password=String(req.body.password||"");
 const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
 if(!u || !(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"Invalid email or password."});
 req.session.userId=u.id;res.json({user:{id:u.id,email:u.email}});
});
app.post("/api/auth/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/auth/me",(req,res)=>{
 if(!req.session.userId)return res.json({user:null});
 const u=db.prepare("SELECT id,email FROM users WHERE id=?").get(req.session.userId);
 res.json({user:u||null});
});


function normalizeImagePayload(image){
 if(typeof image!=="string" || !image.startsWith("data:image/")) return null;
 // Prototype backend storage adapter. Replace this function with S3/R2/Supabase upload in production.
 return image.length < 1500000 ? image : null;
}

app.get("/api/items",auth,(req,res)=>{
 res.json({items:db.prepare("SELECT * FROM items WHERE user_id=? ORDER BY id DESC").all(req.session.userId)});
});
app.post("/api/items",auth,(req,res)=>{
 const x=req.body||{};
 if(!x.name || !Number.isFinite(Number(x.value)) || !x.currency)return res.status(400).json({error:"Invalid item."});
 const imageData = normalizeImagePayload(x.image);
 const notes = String(x.notes||"").slice(0,2000);
 const info=db.prepare(`INSERT INTO items(user_id,name,value,currency,condition,low,high,category,image_data,notes)
 VALUES(?,?,?,?,?,?,?,?,?,?)`).run(
   req.session.userId,String(x.name),Number(x.value),String(x.currency),String(x.condition||""),
   Number(x.low)||null,Number(x.high)||null,String(x.category||""),imageData,notes
 );
 res.json({item:db.prepare("SELECT * FROM items WHERE id=?").get(info.lastInsertRowid)});
});

app.get("/api/items/:id",auth,(req,res)=>{
 const item=db.prepare("SELECT * FROM items WHERE id=? AND user_id=?").get(Number(req.params.id),req.session.userId);
 if(!item)return res.status(404).json({error:"Item not found."});
 res.json({item});
});
app.patch("/api/items/:id",auth,(req,res)=>{
 const id=Number(req.params.id), x=req.body||{};
 const current=db.prepare("SELECT * FROM items WHERE id=? AND user_id=?").get(id,req.session.userId);
 if(!current)return res.status(404).json({error:"Item not found."});
 const notes=String(x.notes ?? current.notes ?? "").slice(0,2000);
 const condition=String(x.condition ?? current.condition ?? "");
 db.prepare("UPDATE items SET notes=?, condition=? WHERE id=? AND user_id=?").run(notes,condition,id,req.session.userId);
 res.json({item:db.prepare("SELECT * FROM items WHERE id=? AND user_id=?").get(id,req.session.userId)});
});
app.delete("/api/items/:id",auth,(req,res)=>{
 db.prepare("DELETE FROM items WHERE id=? AND user_id=?").run(Number(req.params.id),req.session.userId);
 res.json({ok:true});
});

app.post("/api/identify",upload.single("image"),async(req,res)=>{
 if(!req.file)return res.status(400).json({error:"No image uploaded."});
 if(!process.env.OPENAI_API_KEY)return res.json({demo:true,item_name:"Example item",brand:"Apple",model:"iPhone 13 128GB",category:"Electronics",confidence:.72,notes:"Demo mode"});
 try{
  const dataUrl=`data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;
  const r=await fetch("https://api.openai.com/v1/responses",{method:"POST",headers:{"Authorization":`Bearer ${process.env.OPENAI_API_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({
   model:process.env.OPENAI_MODEL||"gpt-5.6-luna",
   input:[{role:"user",content:[
    {type:"input_text",text:`Identify this resale item. Return ONLY valid JSON:
{"item_name":"...","brand":"... or null","model":"... or null","category":"Electronics|Tools|Games & Consoles|Collectibles|Furniture|Car Parts|Clothing|Watches|Toys|Home & Appliances|Other","confidence":0.0,"notes":"short uncertainty notes"}
Never invent a model number.`},
    {type:"input_image",image_url:dataUrl}
   ]}]
  })});
  const p=await r.json();if(!r.ok)return res.status(r.status).json({error:p?.error?.message||"AI request failed"});
  const text=outputText(p);const match=text.match(/\{[\s\S]*\}/);res.json(JSON.parse(match?match[0]:text));
 }catch(e){res.status(500).json({error:e.message})}
});

const marketplaceMap={
 EBAY_US:{id:"EBAY_US",currency:"USD"},
 EBAY_GB:{id:"EBAY_GB",currency:"GBP"},
 EBAY_DE:{id:"EBAY_DE",currency:"EUR"}
};

async function ebayToken(){
 const id=process.env.EBAY_CLIENT_ID, secret=process.env.EBAY_CLIENT_SECRET;
 if(!id||!secret)return null;
 const basic=Buffer.from(`${id}:${secret}`).toString("base64");
 const r=await fetch("https://api.ebay.com/identity/v1/oauth2/token",{method:"POST",headers:{"Authorization":`Basic ${basic}`,"Content-Type":"application/x-www-form-urlencoded"},body:"grant_type=client_credentials&scope=https%3A%2F%2Fapi.ebay.com%2Foauth%2Fapi_scope"});
 const d=await r.json();if(!r.ok)throw new Error(d.error_description||"eBay token request failed");return d.access_token;
}

function median(a){const s=[...a].sort((x,y)=>x-y),m=Math.floor(s.length/2);return s.length%2?s[m]:(s[m-1]+s[m])/2}
function quantile(a,q){const s=[...a].sort((x,y)=>x-y);const p=(s.length-1)*q,b=Math.floor(p),r=p-b;return s[b+1]!==undefined?s[b]+r*(s[b+1]-s[b]):s[b]}
function robustValuation(prices,condition=1){
 const positive=prices.filter(x=>Number.isFinite(x)&&x>0).sort((a,b)=>a-b);
 if(positive.length<3)throw new Error("Not enough comparable listings.");
 const q1=quantile(positive,.25),q3=quantile(positive,.75),iqr=q3-q1,loFence=q1-1.5*iqr,hiFence=q3+1.5*iqr;
 const clean=positive.filter(x=>x>=loFence&&x<=hiFence);
 const med=median(clean),low=quantile(clean,.25),high=quantile(clean,.75);
 const fair=med*condition;
 return {clean,stats:{median:med,q1:low,q3:high},valuation:{quick:fair*.88,fair,top:fair*1.10,low:low*condition,high:high*condition}};
}

function demoComps(q,condition){
 const base=580, vals=[499,525,549,575,599,610,625,649,690,1200];
 const items=vals.map((p,i)=>({title:`${q} comparable listing ${i+1}`,price:p,condition:i<3?"Used - Good":"Used - Very Good",seller:"Demo seller"}));
 const v=robustValuation(vals,condition);return {demo:true,source:"demo data",currency:"USD",count:v.clean.length,items,stats:v.stats,valuation:v.valuation};
}

app.get("/api/comps",async(req,res)=>{
 const q=String(req.query.q||"").trim(), market=marketplaceMap[req.query.market]||marketplaceMap.EBAY_US, condition=Math.max(.4,Math.min(1,Number(req.query.condition)||1));
 if(!q)return res.status(400).json({error:"Missing search query."});
 try{
  const token=await ebayToken();
  if(!token)return res.json(demoComps(q,condition));
  const url=new URL("https://api.ebay.com/buy/browse/v1/item_summary/search");
  url.searchParams.set("q",q);
  url.searchParams.set("limit","50");
  // Keep comps closer to realistic consumer resale offers:
  // used condition + fixed-price listings, then robust outlier trimming.
  url.searchParams.set("filter","conditions:{USED|VERY_GOOD|GOOD|ACCEPTABLE},buyingOptions:{FIXED_PRICE}");
  const r=await fetch(url,{headers:{"Authorization":`Bearer ${token}`,"X-EBAY-C-MARKETPLACE-ID":market.id}});
  const d=await r.json();if(!r.ok)throw new Error(d?.errors?.[0]?.message||"eBay search failed");
  const terms=q.toLowerCase().split(/\s+/).filter(t=>t.length>1);
  const items=(d.itemSummaries||[])
    .map(x=>{
      const title=(x.title||"");
      const low=title.toLowerCase();
      const matches=terms.filter(t=>low.includes(t)).length;
      return {
        title,
        price:Number(x.price?.value),
        condition:x.condition,
        seller:x.seller?.username||"",
        url:x.itemWebUrl,
        matchScore: terms.length ? matches/terms.length : 0
      };
    })
    .filter(x=>x.price>0 && x.matchScore>=0.5)
    .sort((a,b)=>b.matchScore-a.matchScore);
  const v=robustValuation(items.map(x=>x.price),condition);
  const cleanedSet=new Set(v.clean.map(x=>String(x)));
  const usable=items.filter(x=>cleanedSet.has(String(x.price)));
  res.json({demo:false,source:"eBay Browse API",currency:market.currency,count:v.clean.length,items:usable,stats:v.stats,valuation:v.valuation});
 }catch(e){
 console.warn("eBay unavailable, using demo pricing:",e.message);
 const fallback=demoComps(q,condition);
 fallback.source="Demo pricing — eBay connection pending";
 fallback.ebayPending=true;
 res.json(fallback);
 }

app.listen(process.env.PORT||3000,()=>console.log(`SnapWorth v0.3 running on http://localhost:${process.env.PORT||3000}`));
