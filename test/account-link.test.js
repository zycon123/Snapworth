import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {JSDOM} from 'jsdom';
const html=fs.readFileSync(new URL('../public/account-link.html',import.meta.url),'utf8');
test('email page removes token from address, requires explicit action and never sends it on initial load',async()=>{
 const dom=new JSDOM(html,{url:'https://app.example/account-link.html#purpose=verify&token='+'a'.repeat(64),runScripts:'outside-only'});
 const calls=[];const w=dom.window;
 w.fetch=async(url,options)=>{calls.push({url,body:JSON.parse(options.body)});return {ok:true,json:async()=>({message:'Email confirmed.'})}};
 w.eval(html.match(/<script>([\s\S]*?)<\/script>/)[1]);
 assert.equal(w.location.hash,'');assert.equal(calls.length,0);
 await w.document.getElementById('complete').onsubmit({preventDefault(){}});
 assert.equal(calls.length,1);assert.equal(calls[0].body.token,'a'.repeat(64));
 assert(w.document.getElementById('complete').hidden);assert.match(w.document.getElementById('status').textContent,/confirmed/);
 dom.window.close();
});
