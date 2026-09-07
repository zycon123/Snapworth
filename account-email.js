import { randomBytes, createHash } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { PublicError, text, fetchJson } from './security.js';

export const verificationRequired = env => env.EMAIL_VERIFICATION_REQUIRED === 'true' || (env.NODE_ENV === 'production' && env.PUBLIC_SIGNUP_ENABLED === 'true');
export function emailConfiguration(env) {
  try {
    const origin = new URL(env.PUBLIC_ORIGIN);
    return origin.protocol === 'https:' && origin.origin === env.PUBLIC_ORIGIN &&
      !!env.RESEND_API_KEY && /^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$/.test(env.EMAIL_FROM || '');
  } catch { return false; }
}
export function accountEmail({app,pool,env,limiter,sendMail,fetcher}) {
  const enabled = verificationRequired(env);
  const ready = !!sendMail || emailConfiguration(env);
  if (enabled && !ready) throw new Error('Email verification requires PUBLIC_ORIGIN, EMAIL_FROM and RESEND_API_KEY.');
  const deliver = sendMail || (async message => {
    const result = await fetchJson(fetcher,'https://api.resend.com/emails',{
      method:'POST',headers:{Authorization:`Bearer ${env.RESEND_API_KEY}`,'Content-Type':'application/json'},
      body:JSON.stringify({from:env.EMAIL_FROM,to:[message.to],subject:message.subject,text:message.text})
    },10000);
    if (!result.id) throw new Error('Email delivery unavailable');
  });
  const digest = token => createHash('sha256').update(token).digest('hex');
  const generic = {ok:true,message:'If the account is eligible, an email will arrive shortly. Check your spam folder.'};
  async function init() {
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
      CREATE TABLE IF NOT EXISTS account_tokens (
        token_hash TEXT PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        purpose TEXT NOT NULL,auth_version INTEGER NOT NULL,expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS account_tokens_user_idx ON account_tokens(user_id);`);
    await pool.query('DELETE FROM account_tokens WHERE expires_at < $1',[new Date()]);
  }
  async function issue(user,purpose) {
    // Persistent per-account cooldown and shared daily ceiling, including retries.
    const minute = new Date().toISOString().slice(0,16);
    const day = minute.slice(0,10);
    for (const [key,window,limit] of [[`email:${user.id}`,minute,1],['email:global',day,500]]) {
      const result=await pool.query(`INSERT INTO api_usage(key,window_key,count) VALUES($1,$2,1)
        ON CONFLICT(key,window_key) DO UPDATE SET count=LEAST(api_usage.count+1,$3) RETURNING count`,[key,window,limit+1]);
      if (result.rows[0].count>limit) return;
    }
    const token=randomBytes(32).toString('hex');
    await pool.query('INSERT INTO account_tokens(token_hash,user_id,purpose,auth_version,expires_at) VALUES($1,$2,$3,$4,$5)',
      [digest(token),user.id,purpose,user.auth_version||0,new Date(Date.now()+30*60000)]);
    const link=new URL('/account-link.html',env.PUBLIC_ORIGIN);
    // Fragments keep credentials out of request URLs and access logs.
    link.hash=new URLSearchParams({purpose,token}).toString();
    try {
      await deliver({to:user.email,subject:purpose==='verify'?'Confirm your SnapWorth email':'Reset your SnapWorth password',
        text:`${purpose==='verify'?'Confirm your email address':'Choose a new password'} using this link:\n\n${link.href}\n\nThis link expires in 30 minutes and can be used once. If you did not request this, ignore this email.`});
    } catch {
      await pool.query('DELETE FROM account_tokens WHERE token_hash=$1',[digest(token)]);
      console.error('Account email delivery failed');
      // Same response for existing and absent accounts; never disclose provider errors.
    }
  }
  for (const [path,purpose] of [['resend-verification','verify'],['forgot-password','reset']]) {
    app.post('/api/auth/'+path,limiter,async(req,res)=>{
      if(!ready)throw new PublicError(503,'Account email is not configured yet.');
      const email=text(req.body?.email,254,true).toLowerCase();
      const result=await pool.query('SELECT id,email,email_verified,auth_version FROM users WHERE email=$1',[email]);
      const user=result.rows[0];
      if(user && (purpose==='reset'||!user.email_verified))await issue(user,purpose);
      res.json(generic);
    });
  }
  app.post('/api/auth/complete-email',limiter,async(req,res)=>{
    const purpose=req.body?.purpose,token=req.body?.token;
    if(!['verify','reset'].includes(purpose)||typeof token!=='string'||! /^[a-f0-9]{64}$/.test(token))throw new PublicError(400,'This link is invalid or expired.');
    let hash;
    if(purpose==='reset') {
      const password=req.body?.password;
      if(typeof password!=='string'||password.length<8||Buffer.byteLength(password)>72)throw new PublicError(400,'Use at least 8 characters and at most 72 UTF-8 bytes.');
      hash=await bcrypt.hash(password,12);
    }
    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      const result=await client.query('DELETE FROM account_tokens WHERE token_hash=$1 AND purpose=$2 AND expires_at>$3 RETURNING user_id,auth_version',[digest(token),purpose,new Date()]);
      const record=result.rows[0];
      if(!record)throw new PublicError(400,'This link is invalid or expired.');
      // A compare-and-swap on auth_version also invalidates sibling links and sessions.
      const updated=await client.query(purpose==='reset'
        ? 'UPDATE users SET password_hash=$1,email_verified=true,auth_version=auth_version+1 WHERE id=$2 AND auth_version=$3 RETURNING id'
        : 'UPDATE users SET email_verified=true,auth_version=auth_version+1 WHERE id=$1 AND auth_version=$2 RETURNING id',
        purpose==='reset'?[hash,record.user_id,record.auth_version]:[record.user_id,record.auth_version]);
      if(!updated.rows.length)throw new PublicError(400,'This link is invalid or expired.');
      await client.query('DELETE FROM account_tokens WHERE user_id=$1',[record.user_id]);
      await client.query('COMMIT');
      res.json({ok:true,message:purpose==='reset'?'Password updated. Sign in with your new password.':'Email confirmed. You can now sign in.'});
    } catch(error) { await client.query('ROLLBACK');throw error; }
    finally {client.release();}
  });
  return {init,enabled,issue,generic};
}
