import { MAX_PRICE } from './security.js';

const normalize = value => String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/\bgame cube\b/g,'gamecube').replace(/[^a-z0-9]+/g,' ').trim();
const has = (value, phrase) => (' '+normalize(value)+' ').includes(' '+normalize(phrase)+' ');
const types = {
  plush:['plush','plushie','stuffed animal','stuffed toy'], card:['card','trading card'],
  controller:['controller','gamepad'], console:['console'], game:['game','game disc','cartridge'],
  phone:['phone','iphone','smartphone'], drill:['drill','driver','batteridrill'],
  headphones:['headphones','headset'], watch:['watch'], chair:['chair','stol'],
  table:['table','bord'], shoes:['shoes','sneakers'], figure:['figure','figurine'],
  camera:['camera'], laptop:['laptop','macbook'], television:['television','tv'],
  binder:['binder','album'], stand:['stand','holder'], cable:['cable','adapter'],
};
function productType(query) {
  if (/^(nintendo )?gamecube$/.test(normalize(query)) || /^(sony )?playstation [1-5]$/.test(normalize(query))) return 'console';
  return Object.keys(types).find(type=>types[type].some(word=>has(query,word)));
}
const accessory = ['storage album','display stand','stand','holder','binder','album','case only','box only','empty box','manual only','guide','no disc','no game','for parts','not working','replacement','compatible with','cover','shell','keychain','sticker','poster','strap','cable','adapter'];
export function relevantListing(title, query, market) {
  const type = productType(query);
  if (!type) return false; // A broad name alone is insufficient for a price estimate.
  if (accessory.some(word=>has(title,word)&&!has(query,word))) return false;
  if (['bundle','lot','sealed','collector','collectors','complete in box','cib'].some(word=>has(title,word)&&!has(query,word))) return false;
  if (['EBAY_GB','EBAY_DE'].includes(market) && /\b(ntsc|japanese|japan)\b/.test(normalize(title)) && !/\b(ntsc|japanese|japan)\b/.test(normalize(query))) return false;
  if (market==='EBAY_US' && /\b(pal|japanese|japan)\b/.test(normalize(title)) && !/\b(pal|japanese|japan)\b/.test(normalize(query))) return false;
  const conflicts = { console:['controller','game','cable'], card:['plush','figure','binder'], plush:['card','figure','binder'], game:['controller','console'], phone:['cable'], watch:['cable'] };
  if ((conflicts[type]||[]).some(other=>types[other].some(word=>has(title,word))&&!types[other].some(word=>has(query,word)))) return false;
  // The target type must be stated, including for an inferred console query.
  if (!types[type].some(word=>has(title,word))) return false;
  const terms=normalize(query).split(' ').filter(word=>!['the','a','an','used','good','condition'].includes(word));
  return terms.length > 0 && terms.every(word=>has(title,word));
}
export function comparableItems(listings, query, market, currency) {
  if (!Array.isArray(listings)) return [];
  const seen=new Set();
  return listings.filter(x=>x && typeof x.title==='string' && x.price?.currency===currency && typeof x.price.value!=='boolean')
    .map(x=>({id:x.itemId,title:x.title,price:Number(x.price.value),condition:x.condition,seller:x.seller?.username||'',url:x.itemWebUrl,matchScore:1}))
    .filter(x=>{
      const key=x.id||x.url||normalize(x.title)+'|'+x.price;
      if(seen.has(key)||!Number.isFinite(x.price)||x.price<=0||x.price>MAX_PRICE||!relevantListing(x.title,query,market))return false;
      seen.add(key);return true;
    });
}
function quantile(values,q){const p=(values.length-1)*q,b=Math.floor(p),r=p-b;return values[b+1]!==undefined?values[b]+r*(values[b+1]-values[b]):values[b]}
export function robustValuation(prices,condition=1){
  const positive=prices.filter(x=>Number.isFinite(x)&&x>0&&x<=MAX_PRICE).sort((a,b)=>a-b);
  if(positive.length<3)throw new Error('Not enough comparable listings.');
  const q1=quantile(positive,.25),q3=quantile(positive,.75),iqr=q3-q1;
  const clean=positive.filter(x=>x>=q1-1.5*iqr&&x<=q3+1.5*iqr);
  if(clean.length<3)throw new Error('Not enough comparable listings.');
  const med=quantile(clean,.5),low=quantile(clean,.25),high=quantile(clean,.75),fair=med*condition;
  return {clean,stats:{median:med,q1:low,q3:high},valuation:{quick:fair*.88,fair,top:fair*1.10,low:low*condition,high:high*condition}};
}
