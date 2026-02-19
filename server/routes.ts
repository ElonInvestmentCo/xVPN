import type { Express, Request, Response } from "express";
import { createServer, type Server } from "node:http";
import { createProxyMiddleware } from "http-proxy-middleware";
import { registerStripeRoutes } from "./stripe-routes";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import { db } from "./db";
import { users } from "../shared/schema";
import { eq } from "drizzle-orm";
import { sendVerificationEmail } from "./lib/email";
import { getVpnConfig, verifyVpnAccess } from "./lib/proxy-config";
import { errorLogger } from "./lib/error-logger";
import { registerSchema, loginSchema, verifyEmailSchema } from "./lib/validation-schemas";
import rateLimit from "express-rate-limit";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-this";

// Rate limiting for auth endpoints (max 5 requests per 15 minutes)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: "Too many login/register attempts, please try again later",
  legacyHeaders: false,
} as any);

// Rate limiting for email verification (max 10 requests per hour)
const verifyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: "Too many verification attempts, please try again later",
  legacyHeaders: false,
} as any);

interface AuthRequest extends Request {
  userId?: string;
}

/**
 * Middleware to verify JWT token
 */
function authMiddleware(req: AuthRequest, res: Response, next: any) {
  const token = (req as any).headers.authorization?.split(" ")[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

/**
 * POST /api/register
 * Register a new user with email verification
 * PRODUCTION: Validates input with zod, hashes password, sends verification email
 */
async function handleRegister(req: AuthRequest, res: Response) {
  try {
    // Validate input
    const validationResult = registerSchema.safeParse((req as any).body);
    if (!validationResult.success) {
      return res.status(400).json({ 
        error: "Validation failed",
        details: validationResult.error.errors
      });
    }

    const { username, email, password } = validationResult.data;

    // Check if user already exists
    const existing = await db
      .select()
      .from(users)
      .where(eq(users.username, username))
      .limit(1);

    if (existing.length > 0) {
      return res.status(400).json({ error: "Username already exists" });
    }

    // Check if email already registered
    const emailExisting = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (emailExisting.length > 0) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    const verificationToken = uuidv4();
    const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create user with unverified email
    const newUser = await db
      .insert(users)
      .values({
        id: userId,
        username,
        email,
        password: hashedPassword,
        isVerified: false,
        isPro: false,
        verificationToken,
        verificationTokenExpiry: tokenExpiry,
      })
      .returning();

    // Send verification email
    const protocol = (req as any).protocol || 'https';
    const host = ((req as any).get('host') || 'localhost');
    const baseUrl = `${protocol}://${host}`;
    const emailSent = await sendVerificationEmail(email, username, verificationToken, baseUrl);

    if (!emailSent) {
      console.warn("Verification email failed to send, but account created");
    }

    // Generate JWT token for immediate access (unverified)
    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "24h" });

    return res.status(201).json({
      success: true,
      token,
      user: {
        id: userId,
        username,
        email,
        isPro: false,
        isVerified: false,
      },
      message: "Registration successful. Please check your email to verify your account.",
    });
  } catch (error: any) {
    console.error("Registration error:", error);
    errorLogger.logError(error, {
      endpoint: '/api/register',
      body: { username: ((req as any).body as any).username, email: ((req as any).body as any).email }
    });
    return res.status(500).json({ error: "Registration failed" });
  }
}

/**
 * POST /api/verify-email
 * Verify user email with token
 * PRODUCTION: Validates token, marks user as verified, gates VPN access
 */
async function handleVerifyEmail(req: AuthRequest, res: Response) {
  let userId: string | undefined = undefined;
  try {
    // Validate input
    const validationResult = verifyEmailSchema.safeParse((req as any).body);
    if (!validationResult.success) {
      return res.status(400).json({ 
        error: "Validation failed",
        details: validationResult.error.errors
      });
    }

    const { token, userId: extractedUserId } = validationResult.data;
    userId = extractedUserId;

    // Find user with matching token
    const user = await db
      .select()
      .from(users)
      .where(eq(users.verificationToken, token))
      .limit(1);

    if (user.length === 0) {
      return res.status(400).json({ error: "Invalid or expired verification token" });
    }

    const userRecord = user[0];

    // Check if token expired
    if (userRecord.verificationTokenExpiry && new Date() > userRecord.verificationTokenExpiry) {
      return res.status(400).json({ error: "Verification token has expired" });
    }

    // Update user to verified
    const updated = await db
      .update(users)
      .set({
        isVerified: true,
        verificationToken: null,
        verificationTokenExpiry: null,
        verifiedAt: new Date(),
      })
      .where(eq(users.id, userRecord.id))
      .returning();

    return res.json({
      message: "Email verified successfully",
      verified: true,
      user: {
        id: updated[0].id,
        username: updated[0].username,
        email: updated[0].email,
        isVerified: updated[0].isVerified,
        isPro: updated[0].isPro,
      },
    });
  } catch (error: any) {
    console.error("Email verification error:", error);
    if (userId) {
      errorLogger.logAuthFailure('/api/verify-email', error.message, userId);
    }
    return res.status(500).json({ error: "Email verification failed" });
  }
}

/**
 * POST /api/login
 * Login user and return JWT token
 * PRODUCTION: Validates input, returns JWT for session management
 */
async function handleLogin(req: AuthRequest, res: Response) {
  try {
    // Validate input
    const validationResult = loginSchema.safeParse({
      email: ((req as any).body as any).email,
      password: ((req as any).body as any).password
    });
    if (!validationResult.success) {
      return res.status(400).json({ 
        error: "Validation failed",
        details: validationResult.error.errors
      });
    }

    const { email, password } = validationResult.data;

    // Find user by email (not username - important for backend auth)
    const user = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (user.length === 0) {
      errorLogger.logAuthFailure('/api/login', 'User not found', undefined);
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const userRecord = user[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, userRecord.password);

    if (!isValidPassword) {
      errorLogger.logAuthFailure('/api/login', 'Invalid password', userRecord.id);
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Generate JWT token (valid for 24 hours)
    const token = jwt.sign({ userId: userRecord.id }, JWT_SECRET, { expiresIn: "24h" });

    return res.json({
      token,
      user: {
        id: userRecord.id,
        username: userRecord.username,
        email: userRecord.email,
        isVerified: userRecord.isVerified,
        isPro: userRecord.isPro,
      },
    });
  } catch (error: any) {
    console.error("Login error:", error);
    errorLogger.logError(error, { endpoint: '/api/login' });
    return res.status(500).json({ error: "Login failed" });
  }
}

/**
 * POST /api/create-checkout-session
 * Create Stripe checkout session (requires verified user)
 * PRODUCTION: Validates user verification status before allowing payment
 */
async function handleCreateCheckoutSession(req: AuthRequest, res: Response) {
  try {
    const userId = req.userId;

    if (!userId) {
      return res.status(401).json({ error: "Authentication required" });
    }

    // Find user
    const user = await db
      .select()
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);

    if (user.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const userRecord = user[0];

    // Check if email is verified
    if (!userRecord.isVerified) {
      return res.status(403).json({ error: "Please verify your email before subscribing" });
    }

    // Check if already pro
    if (userRecord.isPro) {
      return res.status(400).json({ error: "User already has an active subscription" });
    }

    const { stripe } = await import("./lib/stripe");
    const protocol = ((req as any).header?.('x-forwarded-proto')) || ((req as any).protocol) || "https";
    const host = ((req as any).header?.('x-forwarded-host')) || ((req as any).get?.('host'));
    const baseUrl = `${protocol}://${host}`;

    // Create checkout session with userId in metadata
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: "Elite Stealth VPN",
              description: "Premium unlimited VPN with advanced security features",
            },
            unit_amount: 1999, // $19.99
            recurring: {
              interval: "month",
            },
          },
          quantity: 1,
        },
      ],
      success_url: `${baseUrl}/?session_id={CHECKOUT_SESSION_ID}&status=success`,
      cancel_url: `${baseUrl}/?status=cancelled`,
      customer_email: userRecord.email,
      metadata: {
        userId, // Critical for webhook to identify user
        planId: "elite_stealth",
        planName: "Elite Stealth",
      },
    });

    return res.json({
      sessionId: session.id,
      url: session.url,
    });
  } catch (error: any) {
    console.error("Checkout session creation error:", error);
    return res.status(500).json({ error: error.message });
  }
}

/**
 * GET /api/user/profile
 * Get current user profile (requires auth)
 */
async function handleGetProfile(req: AuthRequest, res: Response) {
  try {
    const userId = req.userId;

    if (!userId) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const user = await db
      .select()
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);

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
      stripeSubscriptionId: userRecord.stripeSubscriptionId,
    });
  } catch (error: any) {
    console.error("Get profile error:", error);
    return res.status(500).json({ error: error.message });
  }
}

/**
 * GET /api/vpn/config
 * Get VPN proxy configuration for Texas location
 */
async function handleGetVpnConfig(req: AuthRequest, res: Response) {
  try {
    const userId = req.userId;

    if (!userId) {
      return res.status(401).json({ error: "Authentication required" });
    }

    // Verify user has VPN access
    const hasAccess = await verifyVpnAccess(userId);

    if (!hasAccess) {
      return res.status(403).json({ 
        error: "Elite Stealth subscription required for Texas VPN access.",
        requiresSubscription: true 
      });
    }

    // Get VPN configuration
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
        protocol: vpnConfig.protocol,
      },
    });
  } catch (error: any) {
    console.error("Get VPN config error:", error);
    return res.status(500).json({ error: error.message });
  }
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Register Stripe routes (includes webhook handler)
  registerStripeRoutes(app);

  // Auth endpoints
  app.post("/api/register", handleRegister);
  app.post("/api/verify-email", handleVerifyEmail);
  app.post("/api/login", handleLogin);

  // Protected endpoints (require authentication)
  app.post("/api/create-checkout-session", authMiddleware, handleCreateCheckoutSession);
  app.get("/api/user/profile", authMiddleware, handleGetProfile);
  app.get("/api/vpn/config", authMiddleware, handleGetVpnConfig);

  // Proxy to Python backend for other API routes
  app.use(
    "/api",
    createProxyMiddleware({
      target: "http://127.0.0.1:8000",
      changeOrigin: true,
      pathRewrite: { "^/": "/api/" },
    }),
  );

  const httpServer = createServer(app);

  return httpServer;
}
