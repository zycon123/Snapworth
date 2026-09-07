import { test } from 'node:test';
import assert from 'node:assert/strict';
import { relevantListing, comparableItems } from '../pricing.js';

test('matching accepts product-type synonyms while preserving identity',()=>{
  for (const [query,title] of [
    ['Pokemon Mew plush','Pokemon Mew stuffed toy'],
    ['Sony headphones','Sony headset'],
    ['IKEA chair','IKEA stol'],
  ]) assert.equal(relevantListing(title,query,'EBAY_US'),true,title);
  assert.equal(relevantListing('Pokemon Pikachu stuffed toy','Pokemon Mew plush','EBAY_US'),false);
  assert.equal(relevantListing('Generic plush','plush','EBAY_US'),false);
});

test('base models do not mix with premium, storage, or graded variants',()=>{
  for (const [query,title] of [
    ['Apple iPhone 13 phone','Apple iPhone 13 Pro phone'],
    ['Apple iPhone 13 phone','Apple iPhone 13 phone 256GB'],
    ['Nintendo Switch console','Nintendo Switch OLED console'],
    ['Pokemon Mew card','Pokemon Mew card PSA 10'],
    ['Pokemon Mew card','Pokemon Mew holo card'],
    ['Sony PlayStation 5 console','Sony PlayStation 5 slim console'],
  ]) assert.equal(relevantListing(title,query,'EBAY_US'),false,title);
  assert.equal(relevantListing('Apple iPhone 13 Pro phone 256GB','Apple iPhone 13 Pro phone 256GB','EBAY_US'),true);
  const listings=['Apple iPhone 13 phone','Apple iPhone 13 Pro phone','Apple iPhone 13 phone 256GB'].map((title,i)=>({itemId:String(i),title,price:{value:'200',currency:'USD'}}));
  assert.equal(comparableItems(listings,'Apple iPhone 13 phone','EBAY_US','USD').length,1);
});
