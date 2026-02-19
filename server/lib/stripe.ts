import Stripe from "stripe";

if (!process.env.STRIPE_SECRET_KEY) {
  console.warn("WARNING: STRIPE_SECRET_KEY is not set. Stripe features will not work.");
}

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "", {
  apiVersion: "2026-01-28.clover",
});

export const PLANS: Record<string, { name: string; priceInCents: number; interval: "month" | "year" }> = {
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

export async function createCheckoutSession({ 
  planId = "elite_stealth", 
  email,
  userId,
  baseUrl 
}: { 
  planId?: string; 
  email?: string; 
  userId?: string;
  baseUrl: string 
}) {
  const plan = PLANS[planId];
  if (!plan) throw new Error("Invalid plan");

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
          recurring: { interval: plan.interval },
        },
        quantity: 1,
      },
    ],
    success_url: `${baseUrl}/?session_id={CHECKOUT_SESSION_ID}&status=success`,
    cancel_url: `${baseUrl}/?status=cancelled`,
    metadata: {
      planId,
      planName: plan.name,
      userId: userId || "", // Critical for webhook to identify user
    },
  };

  if (email) sessionParams.customer_email = email;

  const session = await stripe.checkout.sessions.create(sessionParams);
  return session;
}

/**
 * Verifies Stripe webhook signature
 * @param body - Raw request body as Buffer
 * @param signature - Stripe signature header
 * @returns Parsed event object if valid, null otherwise
 */
export function verifyWebhookSignature(
  body: Buffer | string,
  signature: string
): Stripe.Event | null {
  try {
    const event = stripe.webhooks.constructEvent(
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

/**
 * Extracts subscription data from checkout session
 * @param session - The Stripe checkout session
 * @returns Object containing subscriptionId and customerId
 */
export function extractSessionData(session: Stripe.Checkout.Session): {
  subscriptionId?: string;
  customerId?: string;
  userId?: string;
} {
  return {
    subscriptionId: typeof session.subscription === "string" 
      ? session.subscription 
      : session.subscription?.id,
    customerId: typeof session.customer === "string"
      ? session.customer
      : session.customer?.id,
    userId: session.metadata?.userId,
  };
}
