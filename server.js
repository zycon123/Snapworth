import express from "express";
import multer from "multer";
import dotenv from "dotenv";
import session from "express-session";
import bcrypt from "bcryptjs";
import pg from "pg";
import connectPgSimple from "connect-pg-simple";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

dotenv.config();
const { Pool } = pg;

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
 
app.use(express.json({limit:"1.5mb"}));

if(!process.env.DATABASE_URL){
  throw new Error("DATABASE_URL is required");
}

const pool=new Pool({
  connectionString:process.env.DATABASE_URL,
  ssl:process.env.NODE_ENV==="production"
    ? {rejectUnauthorized:false}
    : false
});

const PgSession=connectPgSimple(session);

app.use(session({
  store:new PgSession({
    pool,
    createTableIfMissing:true
  }),
  secret:process.env.SESSION_SECRET || "development-only-change-me",
  resave:false,
  saveUninitialized:false,
  cookie:{
    httpOnly:true,
    sameSite:"lax",
    secure:process.env.NODE_ENV==="production",
    maxAge:1000*60*60*24*30

}));

const authLimiter=rateLimit({windowMs:15*60*1000,limit:20,standardHeaders:"draft-7",legacyHeaders:false});
const apiLimiter=rateLimit({windowMs:60*1000,limit:120,standardHeaders:"draft-7",legacyHeaders:false});
app.use("/api",apiLimiter);

async function initDatabase(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS items(
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      value DOUBLE PRECISION NOT NULL,
      currency TEXT NOT NULL,
      condition TEXT,
      low DOUBLE PRECISION,
      high DOUBLE PRECISION,
      category TEXT,
      image_data TEXT,
      notes TEXT,
      saved_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

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

  req.session.userId=String(user.id);

  res.json({
   user:{
    id:user.id,
    email:user.email
   }
  });

 }catch(e){
  if(e.code==="23505"){
   return res.status(409).json({error:"Account already exists."});
  }

  console.error("Register error:",e);
  res.status(500).json({error:"Could not create account."});
 }
});

app.post("/api/auth/login",authLimiter,async(req,res)=>{
 try{
  const email=String(req.body.email||"").trim().toLowerCase();
  const password=String(req.body.password||"");

  const result=await pool.query(
   "SELECT id,email,password_hash FROM users WHERE email=$1",
   [email]
  );

  const u=result.rows[0];

  if(!u || !(await bcrypt.compare(password,u.password_hash))){
   return res.status(401).json({error:"Invalid email or password."});
  }

  req.session.userId=String(u.id);

  res.json({
   user:{
    id:u.id,
    email:u.email
   }
  });

 }catch(e){
  console.error("Login error:",e);
  res.status(500).json({error:"Could not sign in."});
 }
});

app.post("/api/auth/logout",(req,res)=>{
 req.session.destroy(()=>{
  res.json({ok:true});
 });
  });


app.get("/api/auth/me",async(req,res)=>{
 try{
  if(!req.session.userId){
   return res.json({user:null});
  }

  const result=await pool.query(
   "SELECT id,email FROM users WHERE id=$1",
   [req.session.userId]
  );

  res.json({
   user:result.rows[0]||null
  });

 }catch(e){
  console.error("Auth check error:",e);
  res.status(500).json({error:"Could not check account."});
 }
});



function normalizeImagePayload(image){
 if(typeof image!=="string" || !image.startsWith("data:image/")) return null;
 // Prototype backend storage adapter. Replace this function with S3/R2/Supabase upload in production.
 return image.length < 1500000 ? image : null;
}

app.get("/api/items",auth,async(req,res)=>{
 try{
  const result=await pool.query(
   "SELECT * FROM items WHERE user_id=$1 ORDER BY id DESC",
   [req.session.userId]
  );
   });

  res.json({items:result.rows});
 }catch(e){
  console.error("Load items error:",e);
  res.status(500).json({error:"Could not load items."});
 }


app.post("/api/items",auth,async(req,res)=>{
 try{
  const x=req.body||{};

  if(!x.name || !Number.isFinite(Number(x.value)) || !x.currency){
   return res.status(400).json({error:"Invalid item."});
  }

  const imageData=normalizeImagePayload(x.image);
  const notes=String(x.notes||"").slice(0,2000);

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
    Number(x.value),
    String(x.currency),
    String(x.condition||""),
    Number.isFinite(Number(x.low)) ? Number(x.low) : null,
    Number.isFinite(Number(x.high)) ? Number(x.high) : null,
    String(x.category||""),
    imageData,
    notes
   ]
  );

  res.json({item:result.rows[0]});

 }catch(e){
  console.error("Save item error:",e);
  res.status(500).json({error:"Could not save item."});
 }
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
  console.error("Load item error:",e);
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

  const condition=String(
   x.condition ?? current.condition ?? ""
  );

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
  console.error("Update item error:",e);
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
  console.error("Delete item error:",e);
  res.status(500).json({error:"Could not delete item."});
 }
});


app.post("/api/identify",upload.single("image"),async(req,res)=>{
 if(!req.file)return res.status(400).json({error:"No image uploaded."});
 if(!process.env.OPENAI_API_KEY)return res.json({demo:true,item_name:"Example item",brand:"Apple",model:"iPhone 13 128GB",category:"Electronics",confidence:.72,notes:"Demo mode"});
 try{
  const dataUrl=`data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;
  const r=await fetch("https://api.openai.com/v1/responses",{method:"POST",headers:{"Authorization":`Bearer ${process.env.OPENAI_API_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({
   model:process.env.OPENAI_MODEL||"gpt-5.6-luna",
   input:[{role:"user",content:[
    {type:"input_text",text:`You are the item-identification engine for a resale valuation app.

Analyze the photo carefully. Pay special attention to:
- visible brand names and logos
- labels, stickers and printed text
- model numbers, product codes and serial-like identifiers
- distinctive shape, controls, ports, accessories and packaging
- whether the item is generic or a specific branded product

Return ONLY valid JSON in exactly this format:
{
  "item_name":"short resale-friendly product name",
  "brand":"brand name or null",
  "model":"exact model number/name or null",
  "category":"Electronics|Tools|Games & Consoles|Collectibles|Furniture|Car Parts|Clothing|Watches|Toys|Home & Appliances|Other",
  "confidence":0.0,
  "notes":"brief explanation of uncertainty",
  "search_query":"best concise international marketplace search query",
"search_query_no":"best concise Norwegian marketplace search query for FINN.no and Facebook Marketplace",
"needs_more_photos":false,
  "photo_request":"what additional photo would help, or null"
}

Rules:
- Never invent a brand or model.
- Only provide a model when it is visible or strongly identifiable from reliable visual evidence.
- Prefer exact brand + model over a generic description when supported.
- If text or a model label may exist but is not readable, set needs_more_photos to true.
- If the item is generic, say so.
- search_query should be optimized for international resale search, usually brand + model + product type.
- search_query_no must be written for Norwegian buyers and Norwegian marketplace terminology.
- Translate the generic product type into Norwegian, but NEVER translate brand names, model names, model numbers, product codes or proper product names.
- Example: "Nintendo GameCube Controller" -> search_query_no: "Nintendo GameCube kontroller".
- Example: "Makita DDF484 Cordless Drill" -> search_query_no: "Makita DDF484 batteridrill".
- Example: "Pokemon Colosseum Nintendo GameCube" -> keep the game title unchanged.
- confidence must be between 0 and 1.
- If another close-up photo of a label, underside, rear panel, packaging or logo would materially improve identification, explain exactly what photo is needed in photo_request.`},
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


app.get("/api/comps",async(req,res)=>{
 const q=String(req.query.q||"").trim();
const requestedMarket=String(req.query.market||"NORWAY");
const condition=Math.max(.4,Math.min(1,Number(req.query.condition)||1));

if(requestedMarket==="NORWAY"){
 return res.status(503).json({
  pricingUnavailable:true,
  source:"Norwegian market",
  currency:"NOK",
  market:"NORWAY",
  error:"Automatic Norwegian market pricing is not connected yet. Use FINN.no and Facebook Marketplace search to check current Norwegian listings."
 });
}

const market=marketplaceMap[requestedMarket]||marketplaceMap.EBAY_US;
 if(!q){
  return res.status(400).json({error:"Missing search query."});
 }

 try{
  const token=await ebayToken();

  if(!token){
   return res.status(503).json({
    pricingUnavailable:true,
    source:"eBay not connected",
    error:"Live market pricing is not available yet. eBay connection is pending."
   });
  }

  const url=new URL("https://api.ebay.com/buy/browse/v1/item_summary/search");
  url.searchParams.set("q",q);
  url.searchParams.set("limit","50");
  url.searchParams.set(
  "filter",
  "conditions:{USED},buyingOptions:{FIXED_PRICE}"
);
  const r=await fetch(url,{
   headers:{
    "Authorization":`Bearer ${token}`,
    "X-EBAY-C-MARKETPLACE-ID":market.id
   }
  });

  const d=await r.json();

  if(!r.ok){
   throw new Error(d?.errors?.[0]?.message||"eBay search failed");
  }
  const terms=q
    .toLowerCase()
    .split(/\s+/)
    .map(t=>t.replace(/[^a-z0-9]+/g,""))
    .filter(t=>t.length>1);

  function normalizeText(text){
  return String(text||"")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g,"")
    .toLowerCase();
}

const normalizedQuery=normalizeText(q);

  const accessoryWords=[
    "memory card",
    "memorycard",
    "manual only",
    "booklet only",
    "instruction booklet only",
    "guide",
    "strategy guide",
    "carry case",
    "carrying case",
    "carry bag",
    "bag only",
    "case only",
    "box only",
    "artwork only",
    "inlay only",
    "sleeve only",
    "sticker",
    "stickers",
    "no disc",
    "no game",
    "for parts",
    "not working"
  ];

  const bundleWords=[
    "double pack",
    "bundle",
    "two disk",
    "two disc",
    "bonus disc",
    "bonus expansion disc",
    "pokemon box",
    "celebi"
  ];

  const premiumWords=[
    "collector",
    "collectors",
    "mint",
    "sealed",
    "rare",
    "complete in box",
    " cib ",
    "cib",
    "complete edition"
  ];

  function queryHasAny(words){
    return words.some(w=>normalizedQuery.includes(w));
  }

  const queryWantsBundle=queryHasAny(bundleWords);
  const queryWantsPremium=queryHasAny(premiumWords);

  function regionPenalty(title){
    const low=normalizeText(title);

    const explicitPAL=
      low.includes(" pal ") ||
      low.includes("uk pal") ||
      low.includes("european version");

    const explicitNTSC=
      low.includes("ntsc") ||
      low.includes("ntsc-u") ||
      low.includes("usa version");

    const explicitJapan=
      low.includes("japan") ||
      low.includes("japanese") ||
      low.includes("ntsc-j");

    // UK and Germany: prefer PAL, reject explicit NTSC/Japan variants.
    if(requestedMarket==="EBAY_GB" || requestedMarket==="EBAY_DE"){
      if(explicitNTSC || explicitJapan) return 0.45;
      if(explicitPAL) return 0;
    }

    // US: reject explicit PAL/Japan variants.
    if(requestedMarket==="EBAY_US"){
      if(explicitPAL || explicitJapan) return 0.45;
      if(explicitNTSC) return 0;
    }

    return 0;
  }

  const items=(d.itemSummaries||[])
    .map(x=>{
      const title=x.title||"";
      const low=normalizeText(title);

      const matches=terms.filter(t=>low.includes(t)).length;
      const baseScore=terms.length ? matches/terms.length : 0;

      let penalty=0;

      // Wrong accessory instead of the actual item.
      if(accessoryWords.some(word=>
        low.includes(word) &&
        !normalizedQuery.includes(word)
      )){
        penalty+=1;
      }

      // Bundles are substantially different products.
      if(!queryWantsBundle && bundleWords.some(word=>low.includes(word))){
        penalty+=0.5;
      }

      // Collector/CIB premiums should not dominate a normal item search.
      if(!queryWantsPremium && premiumWords.some(word=>low.includes(word))){
        penalty+=0.32;
      }

      penalty+=regionPenalty(title);

      const relevanceScore=Math.max(0,baseScore-penalty);

      return {
        title,
        price:Number(x.price?.value),
        condition:x.condition,
        seller:x.seller?.username||"",
        url:x.itemWebUrl,
        matchScore:Number(relevanceScore.toFixed(3))
      };
    })
    .filter(x=>
      Number.isFinite(x.price) &&
      x.price>0 &&
      x.matchScore>=0.72
    )
    .sort((a,b)=>b.matchScore-a.matchScore);
    
  if(items.length<3){
   return res.status(422).json({
    pricingUnavailable:true,
    source:"eBay Browse API",
    error:"Not enough reliable comparable listings were found for this item."
   });
  }

  const v=robustValuation(items.map(x=>x.price),condition);
  const cleanedSet=new Set(v.clean.map(x=>String(x)));
  const usable=items.filter(x=>cleanedSet.has(String(x.price)));

  res.json({
   demo:false,
   source:"eBay Browse API",
   currency:market.currency,
   count:v.clean.length,
   items:usable,
   stats:v.stats,
   valuation:v.valuation
  });

 }catch(e){
  console.warn("eBay unavailable:",e.message);

  res.status(503).json({
   pricingUnavailable:true,
   source:"eBay connection pending",
   error:"Live market pricing is currently unavailable. Use Search this item to check current listings."
  });
 }
});
async function startServer(){
  try{
    await initDatabase();

    const port=process.env.PORT||3000;

    app.listen(port,()=>{
      console.log(`SnapWorth running on port ${port}`);
    });

  }catch(e){
    console.error("Database startup failed:",e);
    process.exit(1);
  }
}

startServer();
