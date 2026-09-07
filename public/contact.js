fetch('/api/site-info').then(r=>r.ok?r.json():null).then(data=>{
 const target=document.getElementById('supportContact');
 if(target && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(data?.supportEmail||'')){
  const a=document.createElement('a');a.href='mailto:'+encodeURIComponent(data.supportEmail);a.textContent=data.supportEmail;target.replaceChildren(a);
 }
}).catch(()=>{});
