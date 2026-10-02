import express from "express";
import crypto from "crypto";
import multer from "multer";
import pg from "pg";
import { v2 as cloudinary } from "cloudinary";

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024, files: 6 }
});

const { Pool } = pg;

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : null;

const PORT = process.env.PORT || 10000;

const SHOP = process.env.SHOPIFY_SHOP_DOMAIN;
const TOKEN = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
const SECRET = process.env.SHOPIFY_API_SECRET;
const API_VERSION = process.env.SHOPIFY_API_VERSION || "2026-07";

/* =========================================================
   RAZORPAY
========================================================= */

const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;

const RAZORPAY_PLANS = {
  month1: process.env.RAZORPAY_PLAN_1_MONTH,
  month6: process.env.RAZORPAY_PLAN_6_MONTH,
  month12: process.env.RAZORPAY_PLAN_12_MONTH
};

const PLAN_MONTHS = {
  month1: 1,
  month6: 6,
  month12: 12
};

const PLAN_NAMES = {
  month1: "KartWalk PDF Tools - 1 Month",
  month6: "KartWalk PDF Tools - 6 Months",
  month12: "KartWalk PDF Tools - 12 Months"
};

const FREE_LIMIT = 5;

/* =========================================================
   CLOUDINARY
========================================================= */

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

/* =========================================================
   RAZORPAY WEBHOOK
   IMPORTANT: Must be BEFORE express.json()
========================================================= */

app.post(
  "/api/razorpay/subscription-webhook",
  express.raw({ type: "application/json", limit: "1mb" }),
  async (req, res) => {
    try {
      if (!RAZORPAY_WEBHOOK_SECRET) {
        return res.status(500).send("Webhook secret not configured");
      }

      const signature = String(
        req.headers["x-razorpay-signature"] || ""
      );

      const expected = crypto
        .createHmac("sha256", RAZORPAY_WEBHOOK_SECRET)
        .update(req.body)
        .digest("hex");

      if (
        !signature ||
        signature.length !== expected.length ||
        !crypto.timingSafeEqual(
          Buffer.from(signature),
          Buffer.from(expected)
        )
      ) {
        return res.status(401).send("Invalid webhook signature");
      }

      const event = JSON.parse(req.body.toString("utf8"));

      const subscription =
        event?.payload?.subscription?.entity || null;

      const payment =
        event?.payload?.payment?.entity || null;

      const subscriptionId =
        subscription?.id ||
        payment?.subscription_id ||
        "";

      if (!pool || !subscriptionId) {
        return res.json({ ok: true });
      }

      /*
       * A successful captured/charged payment grants access.
       * The payment ID table prevents duplicate webhook
       * deliveries from extending access more than once.
       */
      if (
        event.event === "subscription.charged" ||
        event.event === "payment.captured"
      ) {
        const paymentId = String(payment?.id || "");

        if (paymentId) {
          await grantPaidAccess(subscriptionId, paymentId);
        }
      }

      if (
        event.event === "subscription.authenticated" ||
        event.event === "subscription.activated"
      ) {
        await pool.query(
          `
          UPDATE kartwalk_pdf_subscriptions
          SET status=$2,
              updated_at=NOW()
          WHERE subscription_id=$1
          `,
          [subscriptionId, String(subscription?.status || "active")]
        );
      }

      if (
        event.event === "subscription.paused" ||
        event.event === "subscription.halted" ||
        event.event === "subscription.cancelled" ||
        event.event === "subscription.completed"
      ) {
        await pool.query(
          `
          UPDATE kartwalk_pdf_subscriptions
          SET status=$2,
              updated_at=NOW()
          WHERE subscription_id=$1
          `,
          [
            subscriptionId,
            String(
              subscription?.status ||
                event.event.replace("subscription.", "")
            )
          ]
        );
      }

      return res.json({ ok: true });
    } catch (e) {
      console.error("Razorpay webhook error:", e);

      return res.status(500).send("Webhook error");
    }
  }
);

/* =========================================================
   NORMAL JSON
========================================================= */

app.use(express.json({ limit: "1mb" }));

/* =========================================================
   DATABASE
========================================================= */

async function init() {
  if (!pool) return;

  /* Existing reviews table */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS reviews(
      id BIGSERIAL PRIMARY KEY,
      product_id TEXT NOT NULL,
      customer_id TEXT NOT NULL,
      order_id TEXT NOT NULL,
      rating INT NOT NULL CHECK(rating BETWEEN 1 AND 5),
      title TEXT NOT NULL,
      review TEXT NOT NULL,
      customer_name TEXT,
      images JSONB DEFAULT '[]'::jsonb,
      video TEXT,
      approved BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(product_id,customer_id,order_id)
    )
  `);

  /* Free weekly usage */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS kartwalk_pdf_usage(
      customer_id TEXT NOT NULL,
      week_key TEXT NOT NULL,
      used INT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY(customer_id,week_key)
    )
  `);

  /* Paid subscriptions */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS kartwalk_pdf_subscriptions(
      subscription_id TEXT PRIMARY KEY,
      customer_id TEXT NOT NULL,
      plan_code TEXT NOT NULL,
      plan_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'created',
      paid_until TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  /* Processed Razorpay payments */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS kartwalk_pdf_payments(
      payment_id TEXT PRIMARY KEY,
      subscription_id TEXT NOT NULL,
      customer_id TEXT NOT NULL,
      plan_code TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    kartwalk_pdf_subscriptions_customer_idx
    ON kartwalk_pdf_subscriptions(customer_id)
  `);
}

init().catch(console.error);

/* =========================================================
   SHOPIFY APP PROXY
========================================================= */

function validProxy(req) {
  if (!SECRET) return false;

  const q = { ...req.query };

  const sig = String(q.signature || "");

  delete q.signature;

  const msg = Object.keys(q)
    .sort()
    .map(
      k =>
        `${k}=${
          Array.isArray(q[k]) ? q[k].join(",") : q[k]
        }`
    )
    .join("");

  const digest = crypto
    .createHmac("sha256", SECRET)
    .update(msg)
    .digest("hex");

  return (
    sig.length === digest.length &&
    crypto.timingSafeEqual(
      Buffer.from(sig),
      Buffer.from(digest)
    )
  );
}

function customerId(req) {
  return String(
    req.query.logged_in_customer_id || ""
  ).trim();
}

/* =========================================================
   SHOPIFY GRAPHQL
========================================================= */

async function gql(query, variables = {}) {
  if (!SHOP || !TOKEN) {
    throw new Error("Shopify backend not configured");
  }

  const r = await fetch(
    `https://${SHOP}/admin/api/${API_VERSION}/graphql.json`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": TOKEN
      },
      body: JSON.stringify({
        query,
        variables
      })
    }
  );

  const j = await r.json();

  if (!r.ok || j.errors) {
    throw new Error(
      JSON.stringify(j.errors || j)
    );
  }

  return j.data;
}

/* =========================================================
   CUSTOMER REVIEW ELIGIBILITY
========================================================= */

async function eligible(cid, pid) {
  const q = `
    query($q:String!){
      orders(
        first:50,
        query:$q,
        sortKey:CREATED_AT,
        reverse:true
      ){
        nodes{
          id
          name
          customer{
            id
            firstName
            lastName
          }
          fulfillments{
            displayStatus
            deliveredAt
            fulfillmentLineItems(first:100){
              nodes{
                lineItem{
                  product{
                    id
                  }
                }
              }
            }
          }
        }
      }
    }
  `;

  const d = await gql(q, {
    q: `customer_id:${cid}`
  });

  for (const o of d.orders.nodes) {
    if (
      String(o.customer?.id || "")
        .split("/")
        .pop() !== String(cid)
    ) {
      continue;
    }

    for (const f of o.fulfillments || []) {
      const delivered =
        !!f.deliveredAt ||
        String(f.displayStatus || "")
          .toUpperCase() === "DELIVERED";

      if (!delivered) continue;

      const match =
        f.fulfillmentLineItems.nodes.some(
          n =>
            String(
              n.lineItem?.product?.id || ""
            )
              .split("/")
              .pop() === String(pid)
        );

      if (match) {
        return {
          eligible: true,
          orderId: o.id.split("/").pop(),
          orderName: o.name,
          customerName: [
            o.customer?.firstName,
            o.customer?.lastName
          ]
            .filter(Boolean)
            .join(" ")
        };
      }
    }
  }

  return {
    eligible: false,
    message:
      "Only customers with a delivered order can review this product."
  };
}

/* =========================================================
   CLOUDINARY UPLOAD
========================================================= */

function uploadCloud(
  file,
  resource_type = "image"
) {
  return new Promise(
    (resolve, reject) => {
      const s =
        cloudinary.uploader.upload_stream(
          {
            folder: "kartwalk-reviews",
            resource_type
          },
          (e, r) =>
            e
              ? reject(e)
              : resolve(r.secure_url)
        );

      s.end(file.buffer);
    }
  );
}

/* =========================================================
   PDF ACCESS HELPERS
========================================================= */

function weekKey() {
  /*
   * Weekly free allowance resets Monday.
   * Uses UTC consistently on the server.
   */

  const now = new Date();

  const d = new Date(
    Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate()
    )
  );

  let day = d.getUTCDay();

  if (day === 0) day = 7;

  d.setUTCDate(
    d.getUTCDate() + 4 - day
  );

  const yearStart = new Date(
    Date.UTC(d.getUTCFullYear(), 0, 1)
  );

  const week = Math.ceil(
    ((d - yearStart) / 86400000 + 1) / 7
  );

  return (
    d.getUTCFullYear() +
    "-W" +
    String(week).padStart(2, "0")
  );
}

async function getPaidAccess(cid) {
  const result = await pool.query(
    `
    SELECT
      subscription_id,
      plan_code,
      status,
      paid_until
    FROM kartwalk_pdf_subscriptions
    WHERE customer_id=$1
      AND paid_until IS NOT NULL
      AND paid_until > NOW()
    ORDER BY paid_until DESC
    LIMIT 1
    `,
    [cid]
  );

  if (!result.rowCount) {
    return {
      paid: false,
      paidUntil: null
    };
  }

  return {
    paid: true,
    paidUntil:
      result.rows[0].paid_until
  };
}

async function getUsage(cid) {
  const wk = weekKey();

  const result = await pool.query(
    `
    SELECT used
    FROM kartwalk_pdf_usage
    WHERE customer_id=$1
      AND week_key=$2
    `,
    [cid, wk]
  );

  const used = result.rowCount
    ? Number(result.rows[0].used || 0)
    : 0;

  return {
    used,
    remaining: Math.max(
      0,
      FREE_LIMIT - used
    )
  };
}

async function consumeFreeUse(cid) {
  const wk = weekKey();

  /*
   * Atomic query prevents two browser
   * requests from bypassing the 5-use limit.
   */

  const result = await pool.query(
    `
    INSERT INTO kartwalk_pdf_usage(
      customer_id,
      week_key,
      used
    )
    VALUES($1,$2,1)

    ON CONFLICT(customer_id,week_key)

    DO UPDATE SET
      used=kartwalk_pdf_usage.used+1,
      updated_at=NOW()

    WHERE kartwalk_pdf_usage.used < $3

    RETURNING used
    `,
    [
      cid,
      wk,
      FREE_LIMIT
    ]
  );

  if (!result.rowCount) {
    return {
      allowed: false,
      used: FREE_LIMIT,
      remaining: 0
    };
  }

  const used =
    Number(result.rows[0].used);

  return {
    allowed: true,
    used,
    remaining: Math.max(
      0,
      FREE_LIMIT - used
    )
  };
}

/* =========================================================
   RAZORPAY API
========================================================= */

async function razorpayRequest(
  path,
  options = {}
) {
  if (
    !RAZORPAY_KEY_ID ||
    !RAZORPAY_KEY_SECRET
  ) {
    throw new Error(
      "Razorpay API keys are not configured"
    );
  }

  const auth = Buffer.from(
    `${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`
  ).toString("base64");

  const response = await fetch(
    `https://api.razorpay.com/v1${path}`,
    {
      ...options,

      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data?.error?.description ||
        "Razorpay request failed"
    );
  }

  return data;
}

/* =========================================================
   GRANT PAID ACCESS
========================================================= */

async function grantPaidAccess(
  subscriptionId,
  paymentId
) {
  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    const subResult =
      await client.query(
        `
        SELECT *
        FROM kartwalk_pdf_subscriptions
        WHERE subscription_id=$1
        FOR UPDATE
        `,
        [subscriptionId]
      );

    if (!subResult.rowCount) {
      await client.query("ROLLBACK");
      return false;
    }

    const sub = subResult.rows[0];

    const months =
      PLAN_MONTHS[sub.plan_code];

    if (!months) {
      throw new Error(
        "Unknown subscription plan"
      );
    }

    /*
     * Prevent duplicate webhook/callback
     * from granting the same payment twice.
     */

    const paymentInsert =
      await client.query(
        `
        INSERT INTO kartwalk_pdf_payments(
          payment_id,
          subscription_id,
          customer_id,
          plan_code
        )
        VALUES($1,$2,$3,$4)

        ON CONFLICT(payment_id)
        DO NOTHING

        RETURNING payment_id
        `,
        [
          paymentId,
          subscriptionId,
          sub.customer_id,
          sub.plan_code
        ]
      );

    if (!paymentInsert.rowCount) {
      await client.query("COMMIT");
      return true;
    }

    await client.query(
      `
      UPDATE kartwalk_pdf_subscriptions

      SET
        status='active',

        paid_until=
          (
            CASE
              WHEN paid_until IS NOT NULL
               AND paid_until > NOW()
              THEN paid_until
              ELSE NOW()
            END
          )
          +
          make_interval(months => $2),

        updated_at=NOW()

      WHERE subscription_id=$1
      `,
      [
        subscriptionId,
        months
      ]
    );

    await client.query("COMMIT");

    return true;
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

/* =========================================================
   PDF ACCESS STATUS
========================================================= */

async function pdfStatus(
  req,
  res
) {
  try {
    if (!validProxy(req)) {
      return res.status(401).json({
        allowed: false,
        message:
          "Invalid storefront request."
      });
    }

    const cid = customerId(req);

    if (!cid) {
      return res.status(401).json({
        allowed: false,
        loginRequired: true,
        message:
          "Please sign in to your KartWalk account."
      });
    }

    if (!pool) {
      return res.status(503).json({
        allowed: false,
        message:
          "Access database is unavailable."
      });
    }

    const paid =
      await getPaidAccess(cid);

    const usage =
      await getUsage(cid);

    if (paid.paid) {
      return res.json({
        allowed: true,
        paid: true,
        paidUntil:
          paid.paidUntil,
        used: usage.used,
        limit: FREE_LIMIT,
        remaining:
          usage.remaining
      });
    }

    return res.json({
      allowed:
        usage.used < FREE_LIMIT,
      paid: false,
      used: usage.used,
      limit: FREE_LIMIT,
      remaining:
        usage.remaining
    });
  } catch (e) {
    console.error(
      "PDF status error:",
      e
    );

    return res.status(500).json({
      allowed: false,
      message:
        "Could not check PDF access."
    });
  }
}

/* =========================================================
   PDF CONSUME FREE USE
========================================================= */

async function pdfConsume(
  req,
  res
) {
  try {
    if (!validProxy(req)) {
      return res.status(401).json({
        allowed: false,
        message:
          "Invalid storefront request."
      });
    }

    const cid = customerId(req);

    if (!cid) {
      return res.status(401).json({
        allowed: false,
        loginRequired: true,
        message:
          "Please sign in first."
      });
    }

    if (!pool) {
      return res.status(503).json({
        allowed: false
      });
    }

    const paid =
      await getPaidAccess(cid);

    if (paid.paid) {
      return res.json({
        allowed: true,
        paid: true,
        paidUntil:
          paid.paidUntil
      });
    }

    const result =
      await consumeFreeUse(cid);

    if (!result.allowed) {
      return res.status(403).json({
        allowed: false,
        paid: false,
        used: FREE_LIMIT,
        limit: FREE_LIMIT,
        remaining: 0,
        upgradeRequired: true
      });
    }

    return res.json({
      allowed: true,
      paid: false,
      used: result.used,
      limit: FREE_LIMIT,
      remaining:
        result.remaining
    });
  } catch (e) {
    console.error(
      "PDF consume error:",
      e
    );

    return res.status(500).json({
      allowed: false,
      message:
        "Could not update free usage."
    });
  }
}

/* =========================================================
   CREATE RAZORPAY SUBSCRIPTION
========================================================= */

async function createSubscription(
  req,
  res
) {
  try {
    if (!validProxy(req)) {
      return res.status(401).json({
        success: false,
        message:
          "Invalid storefront request."
      });
    }

    const cid = customerId(req);

    if (!cid) {
      return res.status(401).json({
        success: false,
        loginRequired: true,
        message:
          "Please sign in first."
      });
    }

    if (!pool) {
      return res.status(503).json({
        success: false,
        message:
          "Database unavailable."
      });
    }

    const planCode =
      String(req.body?.plan || "");

    const planId =
      RAZORPAY_PLANS[planCode];

    if (
      !planId ||
      !PLAN_MONTHS[planCode]
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Invalid subscription plan."
      });
    }

    /*
     * total_count: 1
     *
     * This makes each option a fixed-duration
     * purchase instead of silently charging
     * the customer forever.
     */

    const subscription =
      await razorpayRequest(
        "/subscriptions",
        {
          method: "POST",

          body: JSON.stringify({
            plan_id: planId,
            total_count: 1,
            quantity: 1,
            customer_notify: 1,

            notes: {
              customer_id: cid,
              kartwalk_plan:
                planCode
            }
          })
        }
      );

    await pool.query(
      `
      INSERT INTO kartwalk_pdf_subscriptions(
        subscription_id,
        customer_id,
        plan_code,
        plan_id,
        status
      )

      VALUES($1,$2,$3,$4,$5)

      ON CONFLICT(subscription_id)

      DO UPDATE SET
        customer_id=EXCLUDED.customer_id,
        plan_code=EXCLUDED.plan_code,
        plan_id=EXCLUDED.plan_id,
        status=EXCLUDED.status,
        updated_at=NOW()
      `,
      [
        subscription.id,
        cid,
        planCode,
        planId,
        subscription.status ||
          "created"
      ]
    );

    return res.json({
      success: true,
      keyId:
        RAZORPAY_KEY_ID,
      subscriptionId:
        subscription.id,
      description:
        PLAN_NAMES[planCode]
    });
  } catch (e) {
    console.error(
      "Create subscription error:",
      e
    );

    return res.status(500).json({
      success: false,
      message:
        e.message ||
        "Could not create subscription."
    });
  }
}

/* =========================================================
   VERIFY RAZORPAY CHECKOUT
========================================================= */

async function verifySubscription(
  req,
  res
) {
  try {
    if (!validProxy(req)) {
      return res.status(401).json({
        success: false,
        message:
          "Invalid storefront request."
      });
    }

    const cid = customerId(req);

    if (!cid) {
      return res.status(401).json({
        success: false,
        message:
          "Please sign in first."
      });
    }

    const paymentId =
      String(
        req.body
          ?.razorpay_payment_id ||
          ""
      );

    const subscriptionId =
      String(
        req.body
          ?.razorpay_subscription_id ||
          ""
      );

    const signature =
      String(
        req.body
          ?.razorpay_signature ||
          ""
      );

    if (
      !paymentId ||
      !subscriptionId ||
      !signature
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Missing Razorpay payment details."
      });
    }

    const expected =
      crypto
        .createHmac(
          "sha256",
          RAZORPAY_KEY_SECRET
        )
        .update(
          `${paymentId}|${subscriptionId}`
        )
        .digest("hex");

    if (
      signature.length !==
        expected.length ||
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return res.status(401).json({
        success: false,
        message:
          "Payment verification failed."
      });
    }

    /*
     * Make sure this subscription
     * belongs to the signed-in
     * Shopify customer.
     */

    const own =
      await pool.query(
        `
        SELECT customer_id
        FROM kartwalk_pdf_subscriptions
        WHERE subscription_id=$1
          AND customer_id=$2
        `,
        [
          subscriptionId,
          cid
        ]
      );

    if (!own.rowCount) {
      return res.status(403).json({
        success: false,
        message:
          "Subscription does not belong to this customer."
      });
    }

    /*
     * Verify payment with Razorpay server.
     */

    const payment =
      await razorpayRequest(
        `/payments/${encodeURIComponent(
          paymentId
        )}`
      );

    if (
      payment.subscription_id !==
      subscriptionId
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Payment subscription mismatch."
      });
    }

    if (
      payment.status !==
        "captured" &&
      payment.status !==
        "authorized"
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Payment is not successful yet."
      });
    }

    await grantPaidAccess(
      subscriptionId,
      paymentId
    );

    const access =
      await getPaidAccess(cid);

    return res.json({
      success: true,
      paid: true,
      paidUntil:
        access.paidUntil
    });
  } catch (e) {
    console.error(
      "Verify subscription error:",
      e
    );

    return res.status(500).json({
      success: false,
      message:
        e.message ||
        "Payment verification failed."
    });
  }
}

/* =========================================================
   PDF ACCESS ROUTES
========================================================= */

app.get(
  "/pdf-access",
  async (req, res) => {
    const action =
      String(
        req.query.action ||
        "status"
      );

    if (action === "status") {
      return pdfStatus(req, res);
    }

    return res.status(400).json({
      success: false,
      message:
        "Unknown action."
    });
  }
);

app.post(
  "/pdf-access",
  async (req, res) => {
    const action =
      String(req.query.action || "");

    if (action === "consume") {
      return pdfConsume(req, res);
    }

    if (
      action ===
      "create-subscription"
    ) {
      return createSubscription(
        req,
        res
      );
    }

    if (
      action ===
      "verify-subscription"
    ) {
      return verifySubscription(
        req,
        res
      );
    }

    return res.status(400).json({
      success: false,
      message:
        "Unknown action."
    });
  }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/health",
  (req, res) =>
    res.json({
      ok: true,
      service:
        "kartwalk-customer-reviews",
      pdfAccess: true,
      razorpay:
        !!(
          RAZORPAY_KEY_ID &&
          RAZORPAY_KEY_SECRET
        )
    })
);

/* =========================================================
   EXISTING CUSTOMER REVIEWS
========================================================= */

app.get(
  "/eligibility",
  async (req, res) => {
    try {
      if (!validProxy(req)) {
        return res
          .status(401)
          .json({
            eligible: false,
            message:
              "Invalid storefront request."
          });
      }

      const cid =
        customerId(req);

      if (!cid) {
        return res
          .status(401)
          .json({
            eligible: false,
            message:
              "Please sign in to your KartWalk account."
          });
      }

      const pid =
        String(
          req.query.product_id ||
            ""
        );

      if (!pid) {
        return res
          .status(400)
          .json({
            eligible: false,
            message:
              "Missing product."
          });
      }

      res.json(
        await eligible(cid, pid)
      );
    } catch (e) {
      console.error(e);

      res.status(500).json({
        eligible: false,
        message:
          "Could not verify delivery right now."
      });
    }
  }
);

app.get(
  "/reviews",
  async (req, res) => {
    try {
      if (!pool) {
        return res.json({
          reviews: []
        });
      }

      const pid =
        String(
          req.query.product_id ||
            ""
        );

      const r =
        await pool.query(
          `
          SELECT
            rating,
            title,
            review,
            customer_name,
            images,
            video,
            created_at
          FROM reviews
          WHERE product_id=$1
            AND approved=TRUE
          ORDER BY created_at DESC
          `,
          [pid]
        );

      res.json({
        reviews: r.rows.map(
          x => ({
            ...x,
            date:
              new Date(
                x.created_at
              ).toLocaleDateString(
                "en-IN"
              )
          })
        )
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        reviews: []
      });
    }
  }
);

app.post(
  "/submit",

  upload.fields([
    {
      name: "images",
      maxCount: 5
    },
    {
      name: "video",
      maxCount: 1
    }
  ]),

  async (req, res) => {
    try {
      if (!validProxy(req)) {
        return res
          .status(401)
          .json({
            success: false,
            message:
              "Invalid storefront request."
          });
      }

      const cid =
        customerId(req);

      if (!cid) {
        return res
          .status(401)
          .json({
            success: false,
            message:
              "Please sign in first."
          });
      }

      if (!pool) {
        return res
          .status(503)
          .json({
            success: false,
            message:
              "Review database is not configured yet."
          });
      }

      const pid =
        String(
          req.body.product_id ||
            ""
        );

      const check =
        await eligible(
          cid,
          pid
        );

      if (!check.eligible) {
        return res
          .status(403)
          .json({
            success: false,
            message:
              check.message
          });
      }

      const rating =
        Number(
          req.body.rating
        );

      const title =
        String(
          req.body.title || ""
        ).trim();

      const review =
        String(
          req.body.review || ""
        ).trim();

      if (
        !Number.isInteger(
          rating
        ) ||
        rating < 1 ||
        rating > 5 ||
        !title ||
        !review
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Please complete rating, title and review."
          });
      }

      const images = [];

      for (
        const f of
        req.files?.images || []
      ) {
        images.push(
          await uploadCloud(
            f,
            "image"
          )
        );
      }

      let video = null;

      if (
        req.files?.video?.[0]
      ) {
        video =
          await uploadCloud(
            req.files.video[0],
            "video"
          );
      }

      await pool.query(
        `
        INSERT INTO reviews(
          product_id,
          customer_id,
          order_id,
          rating,
          title,
          review,
          customer_name,
          images,
          video
        )

        VALUES(
          $1,$2,$3,$4,$5,
          $6,$7,$8,$9
        )
        `,
        [
          pid,
          cid,
          check.orderId,
          rating,
          title.slice(0, 100),
          review.slice(0, 2000),
          check.customerName ||
            "KartWalk Customer",
          JSON.stringify(images),
          video
        ]
      );

      res.json({
        success: true,
        pending_approval: true
      });
    } catch (e) {
      console.error(e);

      if (
        e.code === "23505"
      ) {
        return res
          .status(409)
          .json({
            success: false,
            message:
              "You already reviewed this delivered order."
          });
      }

      res.status(500).json({
        success: false,
        message:
          "Review could not be submitted."
      });
    }
  }
);

/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  () =>
    console.log(
      `KartWalk Reviews + PDF Access running on ${PORT}`
    )
);
