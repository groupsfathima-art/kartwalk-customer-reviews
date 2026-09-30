import express from "express";
import crypto from "crypto";
import multer from "multer";
import pg from "pg";
import { v2 as cloudinary } from "cloudinary";

const app=express();
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:50*1024*1024,files:6}});
const {Pool}=pg;
const pool=process.env.DATABASE_URL?new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false}}):null;
const PORT=process.env.PORT||10000;
const SHOP=process.env.SHOPIFY_SHOP_DOMAIN;
const TOKEN=process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
const SECRET=process.env.SHOPIFY_API_SECRET;
const API_VERSION=process.env.SHOPIFY_API_VERSION||"2026-07";

cloudinary.config({cloud_name:process.env.CLOUDINARY_CLOUD_NAME,api_key:process.env.CLOUDINARY_API_KEY,api_secret:process.env.CLOUDINARY_API_SECRET,secure:true});
app.use(express.json({limit:"1mb"}));

async function init(){
 if(!pool)return;
 await pool.query(`CREATE TABLE IF NOT EXISTS reviews(
 id BIGSERIAL PRIMARY KEY, product_id TEXT NOT NULL, customer_id TEXT NOT NULL,
 order_id TEXT NOT NULL, rating INT NOT NULL CHECK(rating BETWEEN 1 AND 5),
 title TEXT NOT NULL, review TEXT NOT NULL, customer_name TEXT,
 images JSONB DEFAULT '[]'::jsonb, video TEXT, approved BOOLEAN DEFAULT FALSE,
 created_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(product_id,customer_id,order_id))`);
}
init().catch(console.error);

function validProxy(req){
 if(!SECRET)return false;
 const q={...req.query}; const sig=String(q.signature||""); delete q.signature;
 const msg=Object.keys(q).sort().map(k=>`${k}=${Array.isArray(q[k])?q[k].join(","):q[k]}`).join("");
 const digest=crypto.createHmac("sha256",SECRET).update(msg).digest("hex");
 return sig.length===digest.length && crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(digest));
}
function customerId(req){return String(req.query.logged_in_customer_id||"").trim();}
async function gql(query,variables={}){
 if(!SHOP||!TOKEN)throw new Error("Shopify backend not configured");
 const r=await fetch(`https://${SHOP}/admin/api/${API_VERSION}/graphql.json`,{method:"POST",headers:{"Content-Type":"application/json","X-Shopify-Access-Token":TOKEN},body:JSON.stringify({query,variables})});
 const j=await r.json(); if(!r.ok||j.errors)throw new Error(JSON.stringify(j.errors||j)); return j.data;
}
async function eligible(cid,pid){
 const q=`query($q:String!){orders(first:50,query:$q,sortKey:CREATED_AT,reverse:true){nodes{id name customer{id firstName lastName} fulfillments{displayStatus deliveredAt fulfillmentLineItems(first:100){nodes{lineItem{product{id}}}}}}}}`;
 const d=await gql(q,{q:`customer_id:${cid}`});
 for(const o of d.orders.nodes){
  if(String(o.customer?.id||"").split("/").pop()!==String(cid))continue;
  for(const f of o.fulfillments||[]){
   const delivered=!!f.deliveredAt||String(f.displayStatus||"").toUpperCase()==="DELIVERED";
   if(!delivered)continue;
   const match=f.fulfillmentLineItems.nodes.some(n=>String(n.lineItem?.product?.id||"").split("/").pop()===String(pid));
   if(match)return {eligible:true,orderId:o.id.split("/").pop(),orderName:o.name,customerName:[o.customer?.firstName,o.customer?.lastName].filter(Boolean).join(" ")};
  }
 }
 return {eligible:false,message:"Only customers with a delivered order can review this product."};
}
function uploadCloud(file,resource_type="image"){
 return new Promise((resolve,reject)=>{const s=cloudinary.uploader.upload_stream({folder:"kartwalk-reviews",resource_type},(e,r)=>e?reject(e):resolve(r.secure_url));s.end(file.buffer);});
}

app.get("/health",(req,res)=>res.json({ok:true,service:"kartwalk-customer-reviews"}));

app.get("/eligibility",async(req,res)=>{
 try{
  if(!validProxy(req))return res.status(401).json({eligible:false,message:"Invalid storefront request."});
  const cid=customerId(req); if(!cid)return res.status(401).json({eligible:false,message:"Please sign in to your KartWalk account."});
  const pid=String(req.query.product_id||""); if(!pid)return res.status(400).json({eligible:false,message:"Missing product."});
  res.json(await eligible(cid,pid));
 }catch(e){console.error(e);res.status(500).json({eligible:false,message:"Could not verify delivery right now."});}
});

app.get("/reviews",async(req,res)=>{
 try{
  if(!pool)return res.json({reviews:[]});
  const pid=String(req.query.product_id||"");
  const r=await pool.query("SELECT rating,title,review,customer_name,images,video,created_at FROM reviews WHERE product_id=$1 AND approved=TRUE ORDER BY created_at DESC",[pid]);
  res.json({reviews:r.rows.map(x=>({...x,date:new Date(x.created_at).toLocaleDateString("en-IN")}))});
 }catch(e){console.error(e);res.status(500).json({reviews:[]});}
});

app.post("/submit",upload.fields([{name:"images",maxCount:5},{name:"video",maxCount:1}]),async(req,res)=>{
 try{
  if(!validProxy(req))return res.status(401).json({success:false,message:"Invalid storefront request."});
  const cid=customerId(req); if(!cid)return res.status(401).json({success:false,message:"Please sign in first."});
  if(!pool)return res.status(503).json({success:false,message:"Review database is not configured yet."});
  const pid=String(req.body.product_id||""); const check=await eligible(cid,pid);
  if(!check.eligible)return res.status(403).json({success:false,message:check.message});
  const rating=Number(req.body.rating); const title=String(req.body.title||"").trim(); const review=String(req.body.review||"").trim();
  if(!Number.isInteger(rating)||rating<1||rating>5||!title||!review)return res.status(400).json({success:false,message:"Please complete rating, title and review."});
  const images=[]; for(const f of (req.files?.images||[]))images.push(await uploadCloud(f,"image"));
  let video=null; if(req.files?.video?.[0])video=await uploadCloud(req.files.video[0],"video");
  await pool.query(`INSERT INTO reviews(product_id,customer_id,order_id,rating,title,review,customer_name,images,video)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[pid,cid,check.orderId,rating,title.slice(0,100),review.slice(0,2000),check.customerName||"KartWalk Customer",JSON.stringify(images),video]);
  res.json({success:true,pending_approval:true});
 }catch(e){console.error(e); if(e.code==="23505")return res.status(409).json({success:false,message:"You already reviewed this delivered order."}); res.status(500).json({success:false,message:"Review could not be submitted."});}
});

app.listen(PORT,()=>console.log(`KartWalk Reviews running on ${PORT}`));
