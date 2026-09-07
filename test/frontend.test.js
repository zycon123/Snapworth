import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { JSDOM } from 'jsdom';
const html=fs.readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
function fixture(fetcher){
 const dom=new JSDOM(html,{url:'http://localhost/',runScripts:'outside-only',pretendToBeVisual:true});
 const w=dom.window;
 w.matchMedia=()=>({matches:true,addEventListener(){}});w.scrollTo=()=>{};w.HTMLElement.prototype.scrollIntoView=()=>{};
 w.fetch=fetcher||(async()=>({ok:true,json:async()=>({user:null})}));w.AbortSignal=globalThis.AbortSignal;
 w.localStorage.setItem('snapworth_history_v07','broken-json');
 w.eval(html.match(/<script>([\s\S]*?)<\/script>/)[1]);
 return {dom,w};
}
test('frontend boots with corrupted history; labels are bound and unknown prices stay unknown',async()=>{
 const {dom,w}=fixture();await new Promise(r=>setTimeout(r,0));
 assert.match(w.document.getElementById('historyList').textContent,/No scans/);
 assert.equal(w.eval('inventoryAmount({value:0})'),null);
 assert.equal(w.eval('inventoryAmount({value:null})'),null);
 assert.equal(w.eval('money(null,"NOK")'),'Value unavailable');
 for(const label of w.document.querySelectorAll('label.small'))assert(label.control,label.textContent);
 dom.window.close();
});
test('history never injects untrusted markup or retains blob URLs',async()=>{
 const {dom,w}=fixture();
 w.localStorage.setItem('snapworth_history_v07',JSON.stringify([{name:'<img src=x onerror=alert(1)>',image:'" onerror="alert(1)',value:5,currency:'USD'}]));
 w.eval('renderHistory()');assert.equal(w.document.querySelectorAll('#historyList img').length,0);
 w.eval('saveHistory({name:"Phone",value:10,currency:"USD",image:"blob:expired"})');
 assert(!w.localStorage.getItem('snapworth_history_v07').includes('blob:expired'));
 await new Promise(r=>setTimeout(r,0));
 dom.window.close();
});
test('collection loads pages and keeps currency totals separate',async()=>{
 const urls=[];
 const {dom,w}=fixture(async url=>{urls.push(url);return {ok:true,json:async()=>url==='/api/auth/me'?{user:{id:'a',email:'a@example.test'}}:url.includes('before=')?{items:[{id:'1',name:'Dollar',value:10,currency:'USD'}],nextCursor:null}:{items:[{id:'2',name:'Kroner',value:100,currency:'NOK'}],nextCursor:'2'}}});
 await new Promise(r=>setTimeout(r,20));
 assert(urls.includes('/api/items?before=2'));const total=w.document.getElementById('inventoryTotal').textContent;
 assert.match(total,/NOK/);assert.match(total,/USD/);assert(!total.includes('110'));
 dom.window.close();
});
test('busy action wrapper prevents duplicate requests and reports failures',async()=>{
 const {dom,w}=fixture();let release;w.waitTask=new Promise(resolve=>release=resolve);w.calls=0;
 w.eval("window.run=action('saveDetail',async()=>{window.calls++;await window.waitTask;throw new Error('Could not save')})");
 const first=w.run();await w.run();assert.equal(w.calls,1);assert(w.document.getElementById('saveDetail').disabled);
 release();await first;assert.equal(w.document.getElementById('actionStatus').textContent,'Could not save');assert(!w.document.getElementById('saveDetail').disabled);
 dom.window.close();
});
