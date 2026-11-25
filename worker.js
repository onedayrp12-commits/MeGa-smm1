const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Key",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
};
const json = (data, status=200) => new Response(JSON.stringify(data), {
  status, headers: { "Content-Type":"application/json; charset=utf-8", ...cors }
});
const bad = (message, status=400) => json({error:message}, status);
const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
async function digest(s){ return hex(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
async function passwordHash(password, salt){
  const material = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(salt),iterations:150000,hash:"SHA-256"},material,256));
}
function randomToken(){const b=crypto.getRandomValues(new Uint8Array(32));return btoa(String.fromCharCode(...b)).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");}
async function body(req){try{return await req.json()}catch{return null}}
async function userFor(req, env){
  const token=(req.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
  if(!token)return null;
  const th=await digest(token), now=Math.floor(Date.now()/1000);
  return await env.DB.prepare("SELECT u.id,u.name,u.email,u.balance FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(th,now).first();
}
const services = [
  {id:"tt-campaign",platform:"تيك توك",name:"حملة ترويج للمحتوى",unit:"حملة",price:150,min:1,max:10,description:"إعداد طلب ترويج ومراجعته قبل التنفيذ."},
  {id:"ig-campaign",platform:"إنستجرام",name:"حملة وصول وترويج",unit:"حملة",price:180,min:1,max:10,description:"ترويج عبر قنوات إعلانية مشروعة."},
  {id:"fb-campaign",platform:"فيسبوك",name:"حملة ترويج صفحة أو منشور",unit:"حملة",price:180,min:1,max:10,description:"طلب ترويج صفحة أو منشور ومراجعته."},
];
export default {
 async fetch(req, env){
  const url=new URL(req.url);
  if(req.method==="OPTIONS")return new Response(null,{headers:cors});
  if(url.pathname.startsWith("/api/")){
   if(!env.DB)return bad("قاعدة البيانات غير مربوطة بعد.",503);
   if(url.pathname==="/api/health")return json({ok:true,service:"MeGa SMM"});
   if(url.pathname==="/api/services"&&req.method==="GET")return json({services});
   if(url.pathname==="/api/register"&&req.method==="POST"){
    const b=await body(req); if(!b||!b.name||!b.email||!b.password)return bad("أكمل كل البيانات.");
    if(String(b.password).length<10)return bad("كلمة المرور لازم تكون 10 أحرف على الأقل.");
    const email=String(b.email).trim().toLowerCase();
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return bad("البريد الإلكتروني غير صحيح.");
    const salt=randomToken(), hash=await passwordHash(String(b.password),salt);
    try{
     const r=await env.DB.prepare("INSERT INTO users(name,email,password_hash,password_salt) VALUES(?,?,?,?)").bind(String(b.name).trim(),email,hash,salt).run();
     const token=randomToken(); await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(await digest(token),r.meta.last_row_id,Math.floor(Date.now()/1000)+60*60*24*14).run();
     return json({token,user:{id:r.meta.last_row_id,name:String(b.name).trim(),email,balance:0}},201);
    }catch(e){return bad("البريد مستخدم بالفعل أو حدث خطأ.");}
   }
   if(url.pathname==="/api/login"&&req.method==="POST"){
    const b=await body(req);if(!b||!b.email||!b.password)return bad("اكتب البريد وكلمة المرور.");
    const email=String(b.email).trim().toLowerCase(), u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
    if(!u||await passwordHash(String(b.password),u.password_salt)!==u.password_hash)return bad("بيانات الدخول غير صحيحة.",401);
    const token=randomToken();await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(await digest(token),u.id,Math.floor(Date.now()/1000)+1209600).run();
    return json({token,user:{id:u.id,name:u.name,email:u.email,balance:u.balance}});
   }
   if(url.pathname==="/api/me"&&req.method==="GET"){
    const u=await userFor(req,env);return u?json({user:u}):bad("سجّل الدخول أولاً.",401);
   }
   if(url.pathname==="/api/orders"&&req.method==="POST"){
    const u=await userFor(req,env);if(!u)return bad("سجّل الدخول أولاً.",401);
    const b=await body(req);const s=services.find(x=>x.id===b?.service_id);
    if(!s)return bad("الخدمة غير موجودة.");
    const qty=Number(b.quantity);if(!Number.isInteger(qty)||qty<s.min||qty>s.max)return bad("الكمية غير صحيحة.");
    const target=String(b.target_url||"").trim();if(!/^https:\/\/\S+/i.test(target))return bad("اكتب رابطاً عاماً صحيحاً يبدأ بـ https://");
    const price=s.price*qty;
    const result=await env.DB.prepare("INSERT INTO orders(user_id,platform,service,target_url,quantity,price,notes) VALUES(?,?,?,?,?,?,?)").bind(u.id,s.platform,s.name,target,qty,price,String(b.notes||"").slice(0,500)).run();
    return json({ok:true,order_id:result.meta.last_row_id,status:"قيد المراجعة",message:"وصل طلبك، وسيتم مراجعته قبل التنفيذ."},201);
   }
   if(url.pathname==="/api/orders"&&req.method==="GET"){
    const u=await userFor(req,env);if(!u)return bad("سجّل الدخول أولاً.",401);
    const rows=await env.DB.prepare("SELECT id,platform,service,target_url,quantity,price,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 50").bind(u.id).all();
    return json({orders:rows.results});
   }
   if(url.pathname==="/api/topups"&&req.method==="POST"){
    const u=await userFor(req,env);if(!u)return bad("سجّل الدخول أولاً.",401);
    const b=await body(req), amount=Number(b?.amount);
    if(!Number.isInteger(amount)||amount<50||amount>10000||!b.method||!b.reference)return bad("راجع مبلغ الشحن وطريقة الدفع ورقم العملية.");
    const r=await env.DB.prepare("INSERT INTO topups(user_id,amount,method,reference) VALUES(?,?,?,?)").bind(u.id,amount,String(b.method),String(b.reference).slice(0,100)).run();
    return json({ok:true,topup_id:r.meta.last_row_id,status:"قيد المراجعة"},201);
   }
   if(url.pathname.startsWith("/api/admin/")){
    if(!env.ADMIN_KEY||req.headers.get("X-Admin-Key")!==env.ADMIN_KEY)return bad("غير مصرح.",401);
    if(url.pathname==="/api/admin/orders"&&req.method==="GET"){
     const rows=await env.DB.prepare("SELECT o.*,u.name,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 200").all();return json({orders:rows.results});
    }
    if(url.pathname==="/api/admin/orders/status"&&req.method==="PATCH"){
     const b=await body(req);if(!b?.id||!["قيد المراجعة","مقبول","قيد التنفيذ","مكتمل","مرفوض"].includes(b.status))return bad("بيانات الحالة غير صحيحة.");
     await env.DB.prepare("UPDATE orders SET status=? WHERE id=?").bind(b.status,Number(b.id)).run();return json({ok:true});
    }
    if(url.pathname==="/api/admin/topups"&&req.method==="GET"){
     const rows=await env.DB.prepare("SELECT t.*,u.name,u.email FROM topups t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 200").all();return json({topups:rows.results});
    }
    if(url.pathname==="/api/admin/topups/approve"&&req.method==="POST"){
     const b=await body(req);const id=Number(b?.id);if(!id)return bad("رقم الطلب غير صحيح.");
     const t=await env.DB.prepare("SELECT * FROM topups WHERE id=? AND status='قيد المراجعة'").bind(id).first();if(!t)return bad("طلب الشحن غير موجود أو تمت مراجعته.");
     await env.DB.batch([
      env.DB.prepare("UPDATE topups SET status='مقبول' WHERE id=?").bind(id),
      env.DB.prepare("UPDATE users SET balance=balance+? WHERE id=?").bind(t.amount,t.user_id)
     ]);return json({ok:true});
    }
    return bad("المسار غير موجود.",404);
   }
   return bad("المسار غير موجود.",404);
  }
  return env.ASSETS.fetch(req);
 }
};