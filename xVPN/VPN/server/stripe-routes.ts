import express from "express";
import type { Express, Request, Response } from "express";
import Stripe from "stripe";

if (!process.env.STRIPE_SECRET_KEY) {
  console.warn("WARNING: STRIPE_SECRET_KEY is not set. Stripe features will not work.");
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "");

const PLANS: Record<string, { name: string; priceInCents: number; interval: "month" | "year" }> = {
  elite_stealth: {
    name: "Elite Stealth",
    priceInCents: 1999,
    interval: "month",
  },
  annual_pass: {
    name: "Annual Pass",
    priceInCents: 18900,
    interval: "year",
  },
};

export function registerStripeWebhook(app: Express) {
  app.post(
    "/stripe/webhook",
    express.raw({ type: "application/json" }),
    async (req: Request, res: Response) => {
      const sig = req.headers["stripe-signature"] as string;
      const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

      if (!webhookSecret) {
        console.error("STRIPE_WEBHOOK_SECRET not set");
        return res.status(500).json({ error: "Webhook secret not configured" });
      }

      if (!sig) {
        console.error("No stripe-signature header");
        return res.status(400).json({ error: "Missing stripe-signature header" });
      }

      let event: Stripe.Event;
      try {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
      } catch (err: any) {
        console.error("Webhook signature verification failed:", err.message);
        return res.status(400).json({ error: "Invalid signature" });
      }

      console.log(`[WEBHOOK] Received event: ${event.type} (id: ${event.id})`);

      try {
        switch (event.type) {
          case "checkout.session.completed": {
            const session = event.data.object as Stripe.Checkout.Session;
            const subscriptionId = session.subscription as string;
            const customerId = session.customer as string;
            const email = session.customer_email || session.customer_details?.email || "";
            const planId = session.metadata?.planId || "unknown";
            const planName = session.metadata?.planName || "Unknown";
            const userId = session.metadata?.userId; // Extract userId from metadata
            const plan = PLANS[planId];

            console.log(`[WEBHOOK] checkout.session.completed — customer: ${customerId}, subscription: ${subscriptionId}, email: ${email}, plan: ${planId}, userId: ${userId}`);

            const { db } = await import("./db");
            const { subscribers, payments, users } = await import("../shared/schema");
            const { eq } = await import("drizzle-orm");

            // Update users table if userId is available
            if (userId) {
              try {
                const updateUserResult = await db
                  .update(users)
                  .set({
                    isPro: true,
                    stripeSubscriptionId: subscriptionId,
                  })
                  .where(eq(users.id, userId))
                  .returning();
                console.log(`[WEBHOOK] User updated to Pro — userId: ${userId}, isPro: true, stripeSubscriptionId: ${subscriptionId}`);
              } catch (userErr: any) {
                console.error(`[WEBHOOK] Error updating user to Pro — userId: ${userId}, error: ${userErr.message}`);
              }
            }

            const existing = await db
              .select()
              .from(subscribers)
              .where(eq(subscribers.stripeSubscriptionId, subscriptionId))
              .limit(1);

            if (existing.length === 0) {
              const insertResult = await db.insert(subscribers).values({
                email,
                stripeCustomerId: customerId,
                stripeSubscriptionId: subscriptionId,
                planType: planId,
                planName: planName,
                amount: plan?.priceInCents || 0,
                currency: "usd",
                status: "active",
                isActive: true,
                currentPeriodStart: new Date(),
                currentPeriodEnd: new Date(
                  Date.now() + (plan?.interval === "year" ? 365 : 30) * 24 * 60 * 60 * 1000
                ),
              }).returning();
              console.log(`[WEBHOOK] Subscriber inserted — id: ${insertResult[0]?.id}, isActive: ${insertResult[0]?.isActive}, status: ${insertResult[0]?.status}`);
            } else {
              console.log(`[WEBHOOK] Subscriber already exists (idempotency skip) — id: ${existing[0].id}, isActive: ${existing[0].isActive}`);
            }

            if (session.payment_intent) {
              const existingPayment = await db
                .select()
                .from(payments)
                .where(eq(payments.stripePaymentIntentId, session.payment_intent as string))
                .limit(1);

              if (existingPayment.length === 0) {
                const paymentResult = await db.insert(payments).values({
                  stripePaymentIntentId: session.payment_intent as string,
                  amount: session.amount_total || plan?.priceInCents || 0,
                  currency: "usd",
                  status: "succeeded",
                }).returning();
                console.log(`[WEBHOOK] Payment recorded — id: ${paymentResult[0]?.id}, amount: ${paymentResult[0]?.amount}, status: ${paymentResult[0]?.status}`);
              } else {
                console.log(`[WEBHOOK] Payment already exists (idempotency skip) — id: ${existingPayment[0].id}`);
              }
            }

            const verification = await db
              .select()
              .from(subscribers)
              .where(eq(subscribers.stripeSubscriptionId, subscriptionId))
              .limit(1);
            console.log(`[WEBHOOK] Premium flag verification — isActive: ${verification[0]?.isActive}, status: ${verification[0]?.status}, planType: ${verification[0]?.planType}`);

            break;
          }

          case "customer.subscription.updated": {
            const subscription = event.data.object as Stripe.Subscription;
            const customerId = subscription.customer as string;
            console.log(`[WEBHOOK] customer.subscription.updated — customer: ${customerId}, subscription: ${subscription.id}, status: ${subscription.status}`);

            const { db } = await import("./db");
            const { subscribers } = await import("../shared/schema");
            const { eq } = await import("drizzle-orm");

            const items = subscription.items?.data?.[0];
            const periodStart = items?.current_period_start
              ? new Date(items.current_period_start * 1000)
              : new Date();
            const periodEnd = items?.current_period_end
              ? new Date(items.current_period_end * 1000)
              : new Date();

            const updateResult = await db
              .update(subscribers)
              .set({
                status: subscription.status,
                isActive: subscription.status === "active",
                currentPeriodStart: periodStart,
                currentPeriodEnd: periodEnd,
                updatedAt: new Date(),
              })
              .where(eq(subscribers.stripeSubscriptionId, subscription.id))
              .returning();
            console.log(`[WEBHOOK] Subscription updated — id: ${updateResult[0]?.id}, isActive: ${updateResult[0]?.isActive}, status: ${updateResult[0]?.status}`);
            break;
          }

          case "customer.subscription.deleted": {
            const subscription = event.data.object as Stripe.Subscription;
            const customerId = subscription.customer as string;
            console.log(`[WEBHOOK] customer.subscription.deleted — customer: ${customerId}, subscription: ${subscription.id}`);

            const { db } = await import("./db");
            const { subscribers } = await import("../shared/schema");
            const { eq } = await import("drizzle-orm");

            const deleteResult = await db
              .update(subscribers)
              .set({
                status: "cancelled",
                isActive: false,
                updatedAt: new Date(),
              })
              .where(eq(subscribers.stripeSubscriptionId, subscription.id))
              .returning();
            console.log(`[WEBHOOK] Subscription cancelled — id: ${deleteResult[0]?.id}, isActive: ${deleteResult[0]?.isActive}, status: ${deleteResult[0]?.status}`);
            break;
          }

          case "invoice.payment_succeeded": {
            const invoice = event.data.object as Stripe.Invoice;
            const customerId = invoice.customer as string;
            const subscriptionId = (invoice as any).subscription as string;
            console.log(`[WEBHOOK] invoice.payment_succeeded — customer: ${customerId}, subscription: ${subscriptionId}, invoice: ${invoice.id}`);

            const { db } = await import("./db");
            const { payments } = await import("../shared/schema");
            const { eq } = await import("drizzle-orm");

            const piId = (invoice as any).payment_intent as string || `inv_${invoice.id}`;

            const existingPayment = await db
              .select()
              .from(payments)
              .where(eq(payments.stripePaymentIntentId, piId))
              .limit(1);

            if (existingPayment.length === 0) {
              const paymentResult = await db.insert(payments).values({
                stripePaymentIntentId: piId,
                amount: (invoice as any).amount_paid || 0,
                currency: invoice.currency || "usd",
                status: "succeeded",
              }).returning();
              console.log(`[WEBHOOK] Invoice payment recorded — id: ${paymentResult[0]?.id}, amount: ${paymentResult[0]?.amount}, status: ${paymentResult[0]?.status}`);
            } else {
              console.log(`[WEBHOOK] Invoice payment already exists (idempotency skip) — id: ${existingPayment[0].id}`);
            }
            break;
          }
        }
      } catch (err: any) {
        console.error("Webhook handler error:", err.message);
      }

      return res.json({ received: true });
    }
  );
}

export function registerStripeRoutes(app: Express) {
  app.post("/stripe/create-checkout-session", async (req: Request, res: Response) => {
    try {
      if (!process.env.STRIPE_SECRET_KEY) {
        return res.status(500).json({ error: "Stripe is not configured" });
      }

      const { planId, email } = req.body as { planId: string; email?: string };

      const plan = PLANS[planId];
      if (!plan) {
        return res.status(400).json({ error: "Invalid plan" });
      }

      const protocol = req.header("x-forwarded-proto") || req.protocol || "https";
      const host = req.header("x-forwarded-host") || req.get("host");
      const baseUrl = `${protocol}://${host}`;

      const sessionParams: Stripe.Checkout.SessionCreateParams = {
        payment_method_types: ["card"],
        mode: "subscription",
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: `xVPN ${plan.name}`,
                description: plan.interval === "month"
                  ? "Elite Stealth VPN - Monthly subscription"
                  : "Annual Pass VPN - Yearly subscription",
              },
              unit_amount: plan.priceInCents,
              recurring: {
                interval: plan.interval,
              },
            },
            quantity: 1,
          },
        ],
        success_url: `${baseUrl}/?session_id={CHECKOUT_SESSION_ID}&status=success`,
        cancel_url: `${baseUrl}/?status=cancelled`,
        metadata: {
          planId,
          planName: plan.name,
        },
      };

      if (email) {
        sessionParams.customer_email = email;
      }

      const session = await stripe.checkout.sessions.create(sessionParams);

      return res.json({
        sessionId: session.id,
        url: session.url,
      });
    } catch (err: any) {
      console.error("Stripe checkout error:", err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  app.get("/stripe/check-session/:sessionId", async (req: Request, res: Response) => {
    try {
      const session = await stripe.checkout.sessions.retrieve(req.params.sessionId as string);
      return res.json({
        status: session.payment_status,
        subscriptionId: session.subscription,
        planId: session.metadata?.planId,
        planName: session.metadata?.planName,
      });
    } catch (err: any) {
      return res.status(400).json({ error: err.message });
    }
  });

  app.get("/stripe/revenue-dashboard", async (_req: Request, res: Response) => {
    try {
      const { db } = await import("./db");
      const { subscribers, payments } = await import("../shared/schema");

      const allSubscribers = await db.select().from(subscribers);
      const allPayments = await db.select().from(payments);

      const activeSubscribers = allSubscribers.filter((s) => s.isActive);
      const totalRevenue = allPayments
        .filter((p) => p.status === "succeeded")
        .reduce((acc, p) => acc + p.amount, 0);

      const planBreakdown: Record<string, { count: number; revenue: number }> = {};
      for (const sub of allSubscribers) {
        if (!planBreakdown[sub.planType]) {
          planBreakdown[sub.planType] = { count: 0, revenue: 0 };
        }
        planBreakdown[sub.planType].count++;
        planBreakdown[sub.planType].revenue += sub.amount;
      }

      const recentPayments = allPayments
        .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
        .slice(0, 20);

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
          monthlyRevenue: `$${(data.revenue / 100).toFixed(2)}`,
        })),
        recentPayments: recentPayments.map((p) => ({
          id: p.id,
          amount: `$${(p.amount / 100).toFixed(2)}`,
          status: p.status,
          createdAt: p.createdAt,
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
          createdAt: s.createdAt,
        })),
      });
    } catch (err: any) {
      console.error("Revenue dashboard error:", err.message);
      return res.status(500).json({ error: err.message });
    }
  });
}
