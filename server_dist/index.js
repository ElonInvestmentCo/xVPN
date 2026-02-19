var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  insertUserSchema: () => insertUserSchema,
  payments: () => payments,
  subscribers: () => subscribers,
  users: () => users
});
import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, integer, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
var users, subscribers, payments, insertUserSchema;
var init_schema = __esm({
  "shared/schema.ts"() {
    "use strict";
    users = pgTable("users", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      username: text("username").notNull().unique(),
      password: text("password").notNull(),
      email: text("email").notNull().unique(),
      isVerified: boolean("is_verified").notNull().default(false),
      isPro: boolean("is_pro").notNull().default(false),
      stripeSubscriptionId: text("stripe_subscription_id"),
      verificationToken: text("verification_token"),
      verificationTokenExpiry: timestamp("verification_token_expiry"),
      verifiedAt: timestamp("verified_at")
    });
    subscribers = pgTable("subscribers", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      email: text("email").notNull(),
      stripeCustomerId: text("stripe_customer_id").notNull(),
      stripeSubscriptionId: text("stripe_subscription_id"),
      planType: text("plan_type").notNull(),
      planName: text("plan_name").notNull(),
      amount: integer("amount").notNull(),
      currency: text("currency").notNull().default("usd"),
      status: text("status").notNull().default("active"),
      isActive: boolean("is_active").notNull().default(true),
      currentPeriodStart: timestamp("current_period_start"),
      currentPeriodEnd: timestamp("current_period_end"),
      createdAt: timestamp("created_at").notNull().defaultNow(),
      updatedAt: timestamp("updated_at").notNull().defaultNow()
    });
    payments = pgTable("payments", {
      id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
      subscriberId: varchar("subscriber_id").references(() => subscribers.id),
      stripePaymentIntentId: text("stripe_payment_intent_id"),
      amount: integer("amount").notNull(),
      currency: text("currency").notNull().default("usd"),
      status: text("status").notNull(),
      createdAt: timestamp("created_at").notNull().defaultNow()
    });
    insertUserSchema = createInsertSchema(users).pick({
      username: true,
      password: true
    });
  }
});

// server/db.ts
var db_exports = {};
__export(db_exports, {
  checkDatabaseHealth: () => checkDatabaseHealth,
  db: () => db
});
import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
async function checkDatabaseHealth() {
  try {
    const result = await pool.query("SELECT NOW()");
    return !!result.rows[0];
  } catch (error) {
    console.error("[DB] Health check failed:", error);
    return false;
  }
}
var pool, db;
var init_db = __esm({
  "server/db.ts"() {
    "use strict";
    init_schema();
    pool = new pg.Pool({
      connectionString: process.env.DATABASE_URL,
      max: 20,
      // Max simultaneous connections
      idleTimeoutMillis: 3e4,
      // Close idle connections after 30s
      connectionTimeoutMillis: 2e3,
      // 2s timeout for new connections
      statement_timeout: 3e4
      // 30s query timeout
    });
    pool.on("error", (err) => {
      console.error("Unexpected database pool error:", err);
    });
    pool.on("connect", () => {
      console.log("[DB] New connection established");
    });
    pool.on("remove", () => {
      console.log("[DB] Connection removed from pool");
    });
    db = drizzle(pool, { schema: schema_exports });
  }
});

// server/lib/stripe.ts
var stripe_exports = {};
__export(stripe_exports, {
  PLANS: () => PLANS2,
  createCheckoutSession: () => createCheckoutSession,
  extractSessionData: () => extractSessionData,
  stripe: () => stripe2,
  verifyWebhookSignature: () => verifyWebhookSignature
});
import Stripe2 from "stripe";
async function createCheckoutSession({
  planId = "elite_stealth",
  email,
  userId,
  baseUrl
}) {
  const plan = PLANS2[planId];
  if (!plan) throw new Error("Invalid plan");
  const sessionParams = {
    payment_method_types: ["card"],
    mode: "subscription",
    line_items: [
      {
        price_data: {
          currency: "usd",
          product_data: {
            name: `xVPN ${plan.name}`,
            description: plan.interval === "month" ? "Elite Stealth VPN - Monthly subscription" : "Annual Pass VPN - Yearly subscription"
          },
          unit_amount: plan.priceInCents,
          recurring: { interval: plan.interval }
        },
        quantity: 1
      }
    ],
    success_url: `${baseUrl}/?session_id={CHECKOUT_SESSION_ID}&status=success`,
    cancel_url: `${baseUrl}/?status=cancelled`,
    metadata: {
      planId,
      planName: plan.name,
      userId: userId || ""
      // Critical for webhook to identify user
    }
  };
  if (email) sessionParams.customer_email = email;
  const session = await stripe2.checkout.sessions.create(sessionParams);
  return session;
}
function verifyWebhookSignature(body, signature) {
  try {
    const event = stripe2.webhooks.constructEvent(
      body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET || ""
    );
    return event;
  } catch (error) {
    console.error("Webhook signature verification failed:", error);
    return null;
  }
}
function extractSessionData(session) {
  return {
    subscriptionId: typeof session.subscription === "string" ? session.subscription : session.subscription?.id,
    customerId: typeof session.customer === "string" ? session.customer : session.customer?.id,
    userId: session.metadata?.userId
  };
}
var stripe2, PLANS2;
var init_stripe = __esm({
  "server/lib/stripe.ts"() {
    "use strict";
    if (!process.env.STRIPE_SECRET_KEY) {
      console.warn("WARNING: STRIPE_SECRET_KEY is not set. Stripe features will not work.");
    }
    stripe2 = new Stripe2(process.env.STRIPE_SECRET_KEY || "", {
      apiVersion: "2026-01-28.clover"
    });
    PLANS2 = {
      elite_stealth: {
        name: "Elite Stealth",
        priceInCents: 1999,
        interval: "month"
      },
      annual_pass: {
        name: "Annual Pass",
        priceInCents: 18900,
        interval: "year"
      }
    };
  }
});

// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "node:http";
import { createProxyMiddleware } from "http-proxy-middleware";

// server/stripe-routes.ts
import express from "express";
import Stripe from "stripe";
if (!process.env.STRIPE_SECRET_KEY) {
  console.warn("WARNING: STRIPE_SECRET_KEY is not set. Stripe features will not work.");
}
var stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "");
var PLANS = {
  elite_stealth: {
    name: "Elite Stealth",
    priceInCents: 1999,
    interval: "month"
  },
  annual_pass: {
    name: "Annual Pass",
    priceInCents: 18900,
    interval: "year"
  }
};
function registerStripeWebhook(app2) {
  app2.post(
    "/stripe/webhook",
    express.raw({ type: "application/json" }),
    async (req, res) => {
      const sig = req.headers["stripe-signature"];
      const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
      if (!webhookSecret) {
        console.error("STRIPE_WEBHOOK_SECRET not set");
        return res.status(500).json({ error: "Webhook secret not configured" });
      }
      if (!sig) {
        console.error("No stripe-signature header");
        return res.status(400).json({ error: "Missing stripe-signature header" });
      }
      let event;
      try {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
      } catch (err) {
        console.error("Webhook signature verification failed:", err.message);
        return res.status(400).json({ error: "Invalid signature" });
      }
      console.log(`[WEBHOOK] Received event: ${event.type} (id: ${event.id})`);
      try {
        switch (event.type) {
          case "checkout.session.completed": {
            const session = event.data.object;
            const subscriptionId = session.subscription;
            const customerId = session.customer;
            const email = session.customer_email || session.customer_details?.email || "";
            const planId = session.metadata?.planId || "unknown";
            const planName = session.metadata?.planName || "Unknown";
            const userId = session.metadata?.userId;
            const plan = PLANS[planId];
            console.log(`[WEBHOOK] checkout.session.completed \u2014 customer: ${customerId}, subscription: ${subscriptionId}, email: ${email}, plan: ${planId}, userId: ${userId}`);
            const { db: db2 } = await Promise.resolve().then(() => (init_db(), db_exports));
            const { subscribers: subscribers2, payments: payments2, users: users2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
            const { eq: eq3 } = await import("drizzle-orm");
            if (userId) {
              try {
                const updateUserResult = await db2.update(users2).set({
                  isPro: true,
                  stripeSubscriptionId: subscriptionId
                }).where(eq3(users2.id, userId)).returning();
                console.log(`[WEBHOOK] User updated to Pro \u2014 userId: ${userId}, isPro: true, stripeSubscriptionId: ${subscriptionId}`);
              } catch (userErr) {
                console.error(`[WEBHOOK] Error updating user to Pro \u2014 userId: ${userId}, error: ${userErr.message}`);
              }
            }
            const existing = await db2.select().from(subscribers2).where(eq3(subscribers2.stripeSubscriptionId, subscriptionId)).limit(1);
            if (existing.length === 0) {
              const insertResult = await db2.insert(subscribers2).values({
                email,
                stripeCustomerId: customerId,
                stripeSubscriptionId: subscriptionId,
                planType: planId,
                planName,
                amount: plan?.priceInCents || 0,
                currency: "usd",
                status: "active",
                isActive: true,
                currentPeriodStart: /* @__PURE__ */ new Date(),
                currentPeriodEnd: new Date(
                  Date.now() + (plan?.interval === "year" ? 365 : 30) * 24 * 60 * 60 * 1e3
                )
              }).returning();
              console.log(`[WEBHOOK] Subscriber inserted \u2014 id: ${insertResult[0]?.id}, isActive: ${insertResult[0]?.isActive}, status: ${insertResult[0]?.status}`);
            } else {
              console.log(`[WEBHOOK] Subscriber already exists (idempotency skip) \u2014 id: ${existing[0].id}, isActive: ${existing[0].isActive}`);
            }
            if (session.payment_intent) {
              const existingPayment = await db2.select().from(payments2).where(eq3(payments2.stripePaymentIntentId, session.payment_intent)).limit(1);
              if (existingPayment.length === 0) {
                const paymentResult = await db2.insert(payments2).values({
                  stripePaymentIntentId: session.payment_intent,
                  amount: session.amount_total || plan?.priceInCents || 0,
                  currency: "usd",
                  status: "succeeded"
                }).returning();
                console.log(`[WEBHOOK] Payment recorded \u2014 id: ${paymentResult[0]?.id}, amount: ${paymentResult[0]?.amount}, status: ${paymentResult[0]?.status}`);
              } else {
                console.log(`[WEBHOOK] Payment already exists (idempotency skip) \u2014 id: ${existingPayment[0].id}`);
              }
            }
            const verification = await db2.select().from(subscribers2).where(eq3(subscribers2.stripeSubscriptionId, subscriptionId)).limit(1);
            console.log(`[WEBHOOK] Premium flag verification \u2014 isActive: ${verification[0]?.isActive}, status: ${verification[0]?.status}, planType: ${verification[0]?.planType}`);
            break;
          }
          case "customer.subscription.updated": {
            const subscription = event.data.object;
            const customerId = subscription.customer;
            console.log(`[WEBHOOK] customer.subscription.updated \u2014 customer: ${customerId}, subscription: ${subscription.id}, status: ${subscription.status}`);
            const { db: db2 } = await Promise.resolve().then(() => (init_db(), db_exports));
            const { subscribers: subscribers2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
            const { eq: eq3 } = await import("drizzle-orm");
            const items = subscription.items?.data?.[0];
            const periodStart = items?.current_period_start ? new Date(items.current_period_start * 1e3) : /* @__PURE__ */ new Date();
            const periodEnd = items?.current_period_end ? new Date(items.current_period_end * 1e3) : /* @__PURE__ */ new Date();
            const updateResult = await db2.update(subscribers2).set({
              status: subscription.status,
              isActive: subscription.status === "active",
              currentPeriodStart: periodStart,
              currentPeriodEnd: periodEnd,
              updatedAt: /* @__PURE__ */ new Date()
            }).where(eq3(subscribers2.stripeSubscriptionId, subscription.id)).returning();
            console.log(`[WEBHOOK] Subscription updated \u2014 id: ${updateResult[0]?.id}, isActive: ${updateResult[0]?.isActive}, status: ${updateResult[0]?.status}`);
            break;
          }
          case "customer.subscription.deleted": {
            const subscription = event.data.object;
            const customerId = subscription.customer;
            console.log(`[WEBHOOK] customer.subscription.deleted \u2014 customer: ${customerId}, subscription: ${subscription.id}`);
            const { db: db2 } = await Promise.resolve().then(() => (init_db(), db_exports));
            const { subscribers: subscribers2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
            const { eq: eq3 } = await import("drizzle-orm");
            const deleteResult = await db2.update(subscribers2).set({
              status: "cancelled",
              isActive: false,
              updatedAt: /* @__PURE__ */ new Date()
            }).where(eq3(subscribers2.stripeSubscriptionId, subscription.id)).returning();
            console.log(`[WEBHOOK] Subscription cancelled \u2014 id: ${deleteResult[0]?.id}, isActive: ${deleteResult[0]?.isActive}, status: ${deleteResult[0]?.status}`);
            break;
          }
          case "invoice.payment_succeeded": {
            const invoice = event.data.object;
            const customerId = invoice.customer;
            const subscriptionId = invoice.subscription;
            console.log(`[WEBHOOK] invoice.payment_succeeded \u2014 customer: ${customerId}, subscription: ${subscriptionId}, invoice: ${invoice.id}`);
            const { db: db2 } = await Promise.resolve().then(() => (init_db(), db_exports));
            const { payments: payments2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
            const { eq: eq3 } = await import("drizzle-orm");
            const piId = invoice.payment_intent || `inv_${invoice.id}`;
            const existingPayment = await db2.select().from(payments2).where(eq3(payments2.stripePaymentIntentId, piId)).limit(1);
            if (existingPayment.length === 0) {
              const paymentResult = await db2.insert(payments2).values({
                stripePaymentIntentId: piId,
                amount: invoice.amount_paid || 0,
                currency: invoice.currency || "usd",
                status: "succeeded"
              }).returning();
              console.log(`[WEBHOOK] Invoice payment recorded \u2014 id: ${paymentResult[0]?.id}, amount: ${paymentResult[0]?.amount}, status: ${paymentResult[0]?.status}`);
            } else {
              console.log(`[WEBHOOK] Invoice payment already exists (idempotency skip) \u2014 id: ${existingPayment[0].id}`);
            }
            break;
          }
        }
      } catch (err) {
        console.error("Webhook handler error:", err.message);
      }
      return res.json({ received: true });
    }
  );
}
function registerStripeRoutes(app2) {
  app2.post("/stripe/create-checkout-session", async (req, res) => {
    try {
      if (!process.env.STRIPE_SECRET_KEY) {
        return res.status(500).json({ error: "Stripe is not configured" });
      }
      const { planId, email } = req.body;
      const plan = PLANS[planId];
      if (!plan) {
        return res.status(400).json({ error: "Invalid plan" });
      }
      const protocol = req.header("x-forwarded-proto") || req.protocol || "https";
      const host = req.header("x-forwarded-host") || req.get("host");
      const baseUrl = `${protocol}://${host}`;
      const sessionParams = {
        payment_method_types: ["card"],
        mode: "subscription",
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: `xVPN ${plan.name}`,
                description: plan.interval === "month" ? "Elite Stealth VPN - Monthly subscription" : "Annual Pass VPN - Yearly subscription"
              },
              unit_amount: plan.priceInCents,
              recurring: {
                interval: plan.interval
              }
            },
            quantity: 1
          }
        ],
        success_url: `${baseUrl}/?session_id={CHECKOUT_SESSION_ID}&status=success`,
        cancel_url: `${baseUrl}/?status=cancelled`,
        metadata: {
          planId,
          planName: plan.name
        }
      };
      if (email) {
        sessionParams.customer_email = email;
      }
      const session = await stripe.checkout.sessions.create(sessionParams);
      return res.json({
        sessionId: session.id,
        url: session.url
      });
    } catch (err) {
      console.error("Stripe checkout error:", err.message);
      return res.status(500).json({ error: err.message });
    }
  });
  app2.get("/stripe/check-session/:sessionId", async (req, res) => {
    try {
      const session = await stripe.checkout.sessions.retrieve(req.params.sessionId);
      return res.json({
        status: session.payment_status,
        subscriptionId: session.subscription,
        planId: session.metadata?.planId,
        planName: session.metadata?.planName
      });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  });
  app2.get("/stripe/revenue-dashboard", async (_req, res) => {
    try {
      const { db: db2 } = await Promise.resolve().then(() => (init_db(), db_exports));
      const { subscribers: subscribers2, payments: payments2 } = await Promise.resolve().then(() => (init_schema(), schema_exports));
      const allSubscribers = await db2.select().from(subscribers2);
      const allPayments = await db2.select().from(payments2);
      const activeSubscribers = allSubscribers.filter((s) => s.isActive);
      const totalRevenue = allPayments.filter((p) => p.status === "succeeded").reduce((acc, p) => acc + p.amount, 0);
      const planBreakdown = {};
      for (const sub of allSubscribers) {
        if (!planBreakdown[sub.planType]) {
          planBreakdown[sub.planType] = { count: 0, revenue: 0 };
        }
        planBreakdown[sub.planType].count++;
        planBreakdown[sub.planType].revenue += sub.amount;
      }
      const recentPayments = allPayments.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()).slice(0, 20);
      return res.json({
        totalRevenue: totalRevenue / 100,
        totalRevenueFormatted: `$${(totalRevenue / 100).toFixed(2)}`,
        totalSubscribers: allSubscribers.length,
        activeSubscribers: activeSubscribers.length,
        cancelledSubscribers: allSubscribers.length - activeSubscribers.length,
        planBreakdown: Object.entries(planBreakdown).map(([plan, data]) => ({
          plan,
          planDisplayName: PLANS[plan]?.name || plan,
          subscriberCount: data.count,
          monthlyRevenue: `$${(data.revenue / 100).toFixed(2)}`
        })),
        recentPayments: recentPayments.map((p) => ({
          id: p.id,
          amount: `$${(p.amount / 100).toFixed(2)}`,
          status: p.status,
          createdAt: p.createdAt
        })),
        subscribers: allSubscribers.map((s) => ({
          id: s.id,
          email: s.email,
          planName: s.planName,
          planType: s.planType,
          status: s.status,
          isActive: s.isActive,
          amount: `$${(s.amount / 100).toFixed(2)}`,
          currentPeriodEnd: s.currentPeriodEnd,
          createdAt: s.createdAt
        }))
      });
    } catch (err) {
      console.error("Revenue dashboard error:", err.message);
      return res.status(500).json({ error: err.message });
    }
  });
}

// server/routes.ts
init_db();
init_schema();
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import { eq as eq2 } from "drizzle-orm";

// server/lib/email.ts
var nodemailer;
var transporter;
try {
  nodemailer = __require("nodemailer");
  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
} catch (error) {
  console.warn("nodemailer module not found. Email functionality will be disabled.");
}
async function sendVerificationEmail(email, username, verificationToken, baseUrl) {
  try {
    const verificationUrl = `${baseUrl}/verify-email?token=${verificationToken}`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify your xVPN Account",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
            <h1 style="color: white; margin: 0;">xVPN Account Verification</h1>
          </div>
          <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px;">
            <p style="color: #333; font-size: 16px;">
              Hello <strong>${username}</strong>,
            </p>
            <p style="color: #666; font-size: 14px; line-height: 1.6;">
              Thank you for signing up for xVPN! To complete your account setup and access our premium VPN services, please verify your email address by clicking the button below.
            </p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${verificationUrl}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; padding: 12px 30px; border-radius: 4px; font-weight: bold;">
                Verify Email Address
              </a>
            </div>
            <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px;">
              Or copy and paste this link in your browser:<br/>
              <code style="color: #667eea; word-break: break-all;">${verificationUrl}</code>
            </p>
            <p style="color: #999; font-size: 12px; text-align: center; margin-top: 20px;">
              This link will expire in 24 hours.
            </p>
            <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
              If you did not sign up for xVPN, please ignore this email.<br/>
              \xA9 2024 xVPN. All rights reserved.
            </p>
          </div>
        </div>
      `
    };
    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
    return true;
  } catch (error) {
    console.error("Error sending verification email:", error);
    return false;
  }
}

// server/lib/proxy-config.ts
init_db();
init_schema();
import { eq } from "drizzle-orm";
var proxyConfig = {
  host: process.env.PROXY_HOST || "64.84.118.42",
  port: parseInt(process.env.PROXY_PORT || "12323", 10),
  username: process.env.PROXY_USER || "14a9e3b3d61ce",
  password: process.env.PROXY_PASS || "f32be24e71",
  location: "USA - Texas",
  provider: "IPRoyal",
  protocol: "socks5"
  // or "http" depending on proxy type
};
async function verifyVpnAccess(userId) {
  try {
    const user = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (user.length === 0) {
      console.warn(`VPN Access Check: User not found (${userId})`);
      return false;
    }
    const userRecord = user[0];
    const hasAccess = userRecord.isVerified && userRecord.isPro;
    if (!hasAccess) {
      console.warn(
        `VPN Access Denied: userId=${userId}, isVerified=${userRecord.isVerified}, isPro=${userRecord.isPro}`
      );
      return false;
    }
    console.log(`VPN Access Granted: userId=${userId}`);
    return true;
  } catch (error) {
    console.error(`VPN Access Check Error: ${error.message}`);
    return false;
  }
}
async function getVpnConfig(userId) {
  const hasAccess = await verifyVpnAccess(userId);
  if (!hasAccess) {
    return null;
  }
  return {
    host: proxyConfig.host,
    port: proxyConfig.port,
    username: proxyConfig.username,
    password: proxyConfig.password,
    location: proxyConfig.location,
    provider: proxyConfig.provider,
    protocol: proxyConfig.protocol
  };
}

// server/lib/error-logger.ts
var ErrorLogger = class {
  isDevelopment = process.env.NODE_ENV !== "production";
  /**
   * Log an error with optional context
   */
  logError(error, context) {
    const timestamp2 = (/* @__PURE__ */ new Date()).toISOString();
    const message = typeof error === "string" ? error : error.message;
    const stack = typeof error !== "string" ? error.stack : void 0;
    const logEntry = {
      timestamp: timestamp2,
      level: "error",
      message,
      stack,
      context
    };
    if (this.isDevelopment) {
      console.error("[ERROR]", JSON.stringify(logEntry, null, 2));
    }
    console.error("[PROD_ERROR]", message);
  }
  /**
   * Log authentication failures
   */
  logAuthFailure(endpoint, reason, userId) {
    this.logError(`Auth failure: ${reason}`, {
      endpoint,
      userId
    });
  }
  /**
   * Log payment/subscription errors
   */
  logPaymentError(error, userId, sessionId) {
    this.logError(error, {
      userId,
      endpoint: "/api/webhooks/stripe",
      context: { sessionId }
    });
  }
  /**
   * Log VPN connection errors
   */
  logVpnError(error, userId) {
    this.logError(error, {
      userId,
      endpoint: "/api/vpn/config"
    });
  }
};
var errorLogger = new ErrorLogger();

// server/lib/validation-schemas.ts
import { z } from "zod";
var registerSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters").max(50, "Username must be less than 50 characters").regex(/^[a-zA-Z0-9_-]+$/, "Username can only contain letters, numbers, underscores, and hyphens"),
  email: z.string().email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 characters").max(128, "Password must be less than 128 characters")
});
var loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(1, "Password is required")
});
var verifyEmailSchema = z.object({
  token: z.string().min(1, "Verification token is required"),
  userId: z.string().uuid("Invalid user ID")
});
var createCheckoutSessionSchema = z.object({
  planId: z.string().optional(),
  successUrl: z.string().url().optional(),
  cancelUrl: z.string().url().optional()
});
var vpnConfigRequestSchema = z.object({
  // Optional - just validates the Bearer token is present in auth middleware
});

// server/routes.ts
import rateLimit from "express-rate-limit";
var JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-this";
var authLimiter = rateLimit({
  windowMs: 15 * 60 * 1e3,
  // 15 minutes
  max: 5,
  message: "Too many login/register attempts, please try again later",
  legacyHeaders: false
});
var verifyLimiter = rateLimit({
  windowMs: 60 * 60 * 1e3,
  // 1 hour
  max: 10,
  message: "Too many verification attempts, please try again later",
  legacyHeaders: false
});
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}
async function handleRegister(req, res) {
  try {
    const validationResult = registerSchema.safeParse(req.body);
    if (!validationResult.success) {
      return res.status(400).json({
        error: "Validation failed",
        details: validationResult.error.errors
      });
    }
    const { username, email, password } = validationResult.data;
    const existing = await db.select().from(users).where(eq2(users.username, username)).limit(1);
    if (existing.length > 0) {
      return res.status(400).json({ error: "Username already exists" });
    }
    const emailExisting = await db.select().from(users).where(eq2(users.email, email)).limit(1);
    if (emailExisting.length > 0) {
      return res.status(400).json({ error: "Email already registered" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    const verificationToken = uuidv4();
    const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1e3);
    const newUser = await db.insert(users).values({
      id: userId,
      username,
      email,
      password: hashedPassword,
      isVerified: false,
      isPro: false,
      verificationToken,
      verificationTokenExpiry: tokenExpiry
    }).returning();
    const protocol = req.protocol || "https";
    const host = req.get("host") || "localhost";
    const baseUrl = `${protocol}://${host}`;
    const emailSent = await sendVerificationEmail(email, username, verificationToken, baseUrl);
    if (!emailSent) {
      console.warn("Verification email failed to send, but account created");
    }
    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "24h" });
    return res.status(201).json({
      success: true,
      token,
      user: {
        id: userId,
        username,
        email,
        isPro: false,
        isVerified: false
      },
      message: "Registration successful. Please check your email to verify your account."
    });
  } catch (error) {
    console.error("Registration error:", error);
    errorLogger.logError(error, {
      endpoint: "/api/register",
      body: { username: req.body.username, email: req.body.email }
    });
    return res.status(500).json({ error: "Registration failed" });
  }
}
async function handleVerifyEmail(req, res) {
  let userId = void 0;
  try {
    const validationResult = verifyEmailSchema.safeParse(req.body);
    if (!validationResult.success) {
      return res.status(400).json({
        error: "Validation failed",
        details: validationResult.error.errors
      });
    }
    const { token, userId: extractedUserId } = validationResult.data;
    userId = extractedUserId;
    const user = await db.select().from(users).where(eq2(users.verificationToken, token)).limit(1);
    if (user.length === 0) {
      return res.status(400).json({ error: "Invalid or expired verification token" });
    }
    const userRecord = user[0];
    if (userRecord.verificationTokenExpiry && /* @__PURE__ */ new Date() > userRecord.verificationTokenExpiry) {
      return res.status(400).json({ error: "Verification token has expired" });
    }
    const updated = await db.update(users).set({
      isVerified: true,
      verificationToken: null,
      verificationTokenExpiry: null,
      verifiedAt: /* @__PURE__ */ new Date()
    }).where(eq2(users.id, userRecord.id)).returning();
    return res.json({
      message: "Email verified successfully",
      verified: true,
      user: {
        id: updated[0].id,
        username: updated[0].username,
        email: updated[0].email,
        isVerified: updated[0].isVerified,
        isPro: updated[0].isPro
      }
    });
  } catch (error) {
    console.error("Email verification error:", error);
    if (userId) {
      errorLogger.logAuthFailure("/api/verify-email", error.message, userId);
    }
    return res.status(500).json({ error: "Email verification failed" });
  }
}
async function handleLogin(req, res) {
  try {
    const validationResult = loginSchema.safeParse({
      email: req.body.email,
      password: req.body.password
    });
    if (!validationResult.success) {
      return res.status(400).json({
        error: "Validation failed",
        details: validationResult.error.errors
      });
    }
    const { email, password } = validationResult.data;
    const user = await db.select().from(users).where(eq2(users.email, email)).limit(1);
    if (user.length === 0) {
      errorLogger.logAuthFailure("/api/login", "User not found", void 0);
      return res.status(401).json({ error: "Invalid email or password" });
    }
    const userRecord = user[0];
    const isValidPassword = await bcrypt.compare(password, userRecord.password);
    if (!isValidPassword) {
      errorLogger.logAuthFailure("/api/login", "Invalid password", userRecord.id);
      return res.status(401).json({ error: "Invalid email or password" });
    }
    const token = jwt.sign({ userId: userRecord.id }, JWT_SECRET, { expiresIn: "24h" });
    return res.json({
      token,
      user: {
        id: userRecord.id,
        username: userRecord.username,
        email: userRecord.email,
        isVerified: userRecord.isVerified,
        isPro: userRecord.isPro
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    errorLogger.logError(error, { endpoint: "/api/login" });
    return res.status(500).json({ error: "Login failed" });
  }
}
async function handleCreateCheckoutSession(req, res) {
  try {
    const userId = req.userId;
    if (!userId) {
      return res.status(401).json({ error: "Authentication required" });
    }
    const user = await db.select().from(users).where(eq2(users.id, userId)).limit(1);
    if (user.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    const userRecord = user[0];
    if (!userRecord.isVerified) {
      return res.status(403).json({ error: "Please verify your email before subscribing" });
    }
    if (userRecord.isPro) {
      return res.status(400).json({ error: "User already has an active subscription" });
    }
    const { stripe: stripe3 } = await Promise.resolve().then(() => (init_stripe(), stripe_exports));
    const protocol = req.header?.("x-forwarded-proto") || req.protocol || "https";
    const host = req.header?.("x-forwarded-host") || req.get?.("host");
    const baseUrl = `${protocol}://${host}`;
    const session = await stripe3.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: "Elite Stealth VPN",
              description: "Premium unlimited VPN with advanced security features"
            },
            unit_amount: 1999,
            // $19.99
            recurring: {
              interval: "month"
            }
          },
          quantity: 1
        }
      ],
      success_url: `${baseUrl}/?session_id={CHECKOUT_SESSION_ID}&status=success`,
      cancel_url: `${baseUrl}/?status=cancelled`,
      customer_email: userRecord.email,
      metadata: {
        userId,
        // Critical for webhook to identify user
        planId: "elite_stealth",
        planName: "Elite Stealth"
      }
    });
    return res.json({
      sessionId: session.id,
      url: session.url
    });
  } catch (error) {
    console.error("Checkout session creation error:", error);
    return res.status(500).json({ error: error.message });
  }
}
async function handleGetProfile(req, res) {
  try {
    const userId = req.userId;
    if (!userId) {
      return res.status(401).json({ error: "Authentication required" });
    }
    const user = await db.select().from(users).where(eq2(users.id, userId)).limit(1);
    if (user.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    const userRecord = user[0];
    return res.json({
      id: userRecord.id,
      username: userRecord.username,
      email: userRecord.email,
      isVerified: userRecord.isVerified,
      isPro: userRecord.isPro,
      stripeSubscriptionId: userRecord.stripeSubscriptionId
    });
  } catch (error) {
    console.error("Get profile error:", error);
    return res.status(500).json({ error: error.message });
  }
}
async function handleGetVpnConfig(req, res) {
  try {
    const userId = req.userId;
    if (!userId) {
      return res.status(401).json({ error: "Authentication required" });
    }
    const hasAccess = await verifyVpnAccess(userId);
    if (!hasAccess) {
      return res.status(403).json({
        error: "Elite Stealth subscription required for Texas VPN access.",
        requiresSubscription: true
      });
    }
    const vpnConfig = await getVpnConfig(userId);
    if (!vpnConfig) {
      return res.status(403).json({
        error: "Elite Stealth subscription required for Texas VPN access.",
        requiresSubscription: true
      });
    }
    return res.json({
      success: true,
      location: vpnConfig.location,
      provider: vpnConfig.provider,
      proxy: {
        host: vpnConfig.host,
        port: vpnConfig.port,
        username: vpnConfig.username,
        password: vpnConfig.password,
        protocol: vpnConfig.protocol
      }
    });
  } catch (error) {
    console.error("Get VPN config error:", error);
    return res.status(500).json({ error: error.message });
  }
}
async function registerRoutes(app2) {
  registerStripeRoutes(app2);
  app2.post("/api/register", handleRegister);
  app2.post("/api/verify-email", handleVerifyEmail);
  app2.post("/api/login", handleLogin);
  app2.post("/api/create-checkout-session", authMiddleware, handleCreateCheckoutSession);
  app2.get("/api/user/profile", authMiddleware, handleGetProfile);
  app2.get("/api/vpn/config", authMiddleware, handleGetVpnConfig);
  app2.use(
    "/api",
    createProxyMiddleware({
      target: "http://127.0.0.1:8000",
      changeOrigin: true,
      pathRewrite: { "^/": "/api/" }
    })
  );
  const httpServer = createServer(app2);
  return httpServer;
}

// server/index.ts
import * as fs from "fs";
import * as path from "path";
var app = express2();
var log = console.log;
function setupCors(app2) {
  app2.use((req, res, next) => {
    const origins = /* @__PURE__ */ new Set();
    if (process.env.REPLIT_DEV_DOMAIN) {
      origins.add(`https://${process.env.REPLIT_DEV_DOMAIN}`);
    }
    if (process.env.REPLIT_DOMAINS) {
      process.env.REPLIT_DOMAINS.split(",").forEach((d) => {
        origins.add(`https://${d.trim()}`);
      });
    }
    const origin = req.header("origin");
    const isLocalhost = origin?.startsWith("http://localhost:") || origin?.startsWith("http://127.0.0.1:");
    if (origin && (origins.has(origin) || isLocalhost)) {
      res.header("Access-Control-Allow-Origin", origin);
      res.header(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, OPTIONS"
      );
      res.header("Access-Control-Allow-Headers", "Content-Type");
      res.header("Access-Control-Allow-Credentials", "true");
    }
    if (req.method === "OPTIONS") {
      return res.sendStatus(200);
    }
    next();
  });
}
function setupBodyParsing(app2) {
  app2.use(express2.json());
  app2.use(express2.urlencoded({ extended: false }));
}
function setupRequestLogging(app2) {
  app2.use((req, res, next) => {
    const start = Date.now();
    const path2 = req.path;
    let capturedJsonResponse = void 0;
    const originalResJson = res.json;
    res.json = function(bodyJson, ...args) {
      capturedJsonResponse = bodyJson;
      return originalResJson.apply(res, [bodyJson, ...args]);
    };
    res.on("finish", () => {
      if (!path2.startsWith("/api")) return;
      const duration = Date.now() - start;
      let logLine = `${req.method} ${path2} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    });
    next();
  });
}
function getAppName() {
  try {
    const appJsonPath = path.resolve(process.cwd(), "app.json");
    const appJsonContent = fs.readFileSync(appJsonPath, "utf-8");
    const appJson = JSON.parse(appJsonContent);
    return appJson.expo?.name || "App Landing Page";
  } catch {
    return "App Landing Page";
  }
}
function serveExpoManifest(platform, res) {
  const manifestPath = path.resolve(
    process.cwd(),
    "static-build",
    platform,
    "manifest.json"
  );
  if (!fs.existsSync(manifestPath)) {
    return res.status(404).json({ error: `Manifest not found for platform: ${platform}` });
  }
  res.setHeader("expo-protocol-version", "1");
  res.setHeader("expo-sfv-version", "0");
  res.setHeader("content-type", "application/json");
  const manifest = fs.readFileSync(manifestPath, "utf-8");
  res.send(manifest);
}
function serveLandingPage({
  req,
  res,
  landingPageTemplate,
  appName
}) {
  const forwardedProto = req.header("x-forwarded-proto");
  const protocol = forwardedProto || req.protocol || "https";
  const forwardedHost = req.header("x-forwarded-host");
  const host = forwardedHost || req.get("host");
  const baseUrl = `${protocol}://${host}`;
  const expsUrl = `${host}`;
  log(`baseUrl`, baseUrl);
  log(`expsUrl`, expsUrl);
  const html = landingPageTemplate.replace(/BASE_URL_PLACEHOLDER/g, baseUrl).replace(/EXPS_URL_PLACEHOLDER/g, expsUrl).replace(/APP_NAME_PLACEHOLDER/g, appName);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(200).send(html);
}
function configureExpoAndLanding(app2) {
  const templatePath = path.resolve(
    process.cwd(),
    "server",
    "templates",
    "landing-page.html"
  );
  const landingPageTemplate = fs.readFileSync(templatePath, "utf-8");
  const appName = getAppName();
  log("Serving static Expo files with dynamic manifest routing");
  app2.use((req, res, next) => {
    if (req.path.startsWith("/api")) {
      return next();
    }
    if (req.path !== "/" && req.path !== "/manifest") {
      return next();
    }
    const platform = req.header("expo-platform");
    if (platform && (platform === "ios" || platform === "android")) {
      return serveExpoManifest(platform, res);
    }
    if (req.path === "/") {
      return serveLandingPage({
        req,
        res,
        landingPageTemplate,
        appName
      });
    }
    next();
  });
  app2.use("/assets", express2.static(path.resolve(process.cwd(), "assets")));
  app2.use(express2.static(path.resolve(process.cwd(), "static-build")));
  log("Expo routing: Checking expo-platform header on / and /manifest");
}
function setupWebProxy(app2) {
  if (process.env.NODE_ENV !== "development") return;
  const { createProxyMiddleware: createProxyMiddleware2 } = __require("http-proxy-middleware");
  const metroProxy = createProxyMiddleware2({
    target: "http://127.0.0.1:8081",
    changeOrigin: true,
    ws: true,
    logLevel: "silent"
  });
  app2.use((req, res, next) => {
    if (req.path.startsWith("/api")) return next();
    const platform = req.header("expo-platform");
    if (platform && (platform === "ios" || platform === "android")) return next();
    const ua = req.header("user-agent") || "";
    const isWebBrowser = !platform && (ua.includes("Mozilla") || ua.includes("Chrome") || ua.includes("Safari"));
    if (isWebBrowser || req.path.includes("bundle") || req.path.includes("hot") || req.path.includes("__metro")) {
      return metroProxy(req, res, next);
    }
    next();
  });
}
function setupErrorHandler(app2) {
  app2.use((err, _req, res, next) => {
    const error = err;
    const status = error.status || error.statusCode || 500;
    const message = error.message || "Internal Server Error";
    console.error("Internal Server Error:", err);
    if (res.headersSent) {
      return next(err);
    }
    return res.status(status).json({ message });
  });
}
(async () => {
  setupCors(app);
  registerStripeWebhook(app);
  setupBodyParsing(app);
  setupRequestLogging(app);
  const server = await registerRoutes(app);
  setupWebProxy(app);
  configureExpoAndLanding(app);
  setupErrorHandler(app);
  const port = parseInt(process.env.PORT || "5000", 10);
  server.listen(port, "127.0.0.1", () => {
    log(`express server serving on port ${port}`);
  });
})();
