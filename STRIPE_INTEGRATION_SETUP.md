# xVPN Stripe + Email Verification Integration Guide

## Implementation Complete ✅

This document describes the complete Stripe payment + email verification system that has been implemented for the xVPN application.

## Changes Made

### 1. Environment Variables (.env) ✅
**File**: `.env`
- Updated with all required credentials:
  - `DATABASE_URL`: Supabase PostgreSQL connection
  - `EMAIL_USER`: Gmail SMTP credentials (Xvpnsecure@gmail.com)
  - `EMAIL_PASS`: Gmail app password
  - `STRIPE_PUBLISHABLE_KEY`: Test mode publishable key
  - `STRIPE_SECRET_KEY`: Test mode secret key
  - `STRIPE_WEBHOOK_SECRET`: Webhook signature verification key

### 2. Server Library Files Created

#### `server/lib/stripe.ts` ✅
**Purpose**: Stripe client initialization and helpers
**Exports**:
- `stripe`: Initialized Stripe instance
- `PLANS`: Plan definitions (Elite Stealth $19.99/mo, Annual Pass $189/yr)
- `createCheckoutSession()`: Creates Stripe checkout session with userId metadata
- `verifyWebhookSignature()`: Validates webhook signatures
- `extractSessionData()`: Extracts subscription data from sessions

**Key Features**:
- Metadata includes `userId` for webhook tracking
- Supports month/year billing intervals
- Returns session URL for checkout redirect

#### `server/lib/email.ts` ✅
**Purpose**: Email delivery via Gmail SMTP
**Exports**:
- `sendVerificationEmail()`: Sends account verification email
- `sendPasswordResetEmail()`: Sends password reset email

**Key Features**:
- HTML email templates with branding
- 24-hour token expiry for verification
- Nodemailer SMTP integration

### 3. Database Schema Updated

#### `shared/schema.ts` ✅
**Users Table** (Already had):
- `email` (text, unique)
- `isVerified` (boolean, default false)
- `isPro` (boolean, default false)
- `stripeSubscriptionId` (text, nullable)
- `verificationToken` (text, nullable)
- `verificationTokenExpiry` (timestamp)
- `verifiedAt` (timestamp)

**Subscribers & Payments Tables**: Already defined for subscription tracking

### 4. Server Routes Updated

#### `server/routes.ts` ✅
**New Endpoints**:

**Public Endpoints**:
- `POST /api/register`
  - Accept: username, email, password
  - Validates email/username uniqueness
  - Hashes password with bcrypt
  - Creates user with unverified status
  - Sends verification email
  - Returns JWT token + user data

- `POST /api/verify-email`
  - Accept: verification token
  - Validates token and expiry
  - Marks user as verified
  - Returns success confirmation

- `POST /api/login`
  - Accept: username, password
  - Validates credentials
  - Generates JWT token
  - Returns token + user profile

**Protected Endpoints** (require Authorization header: `Bearer <token>`):
- `POST /api/create-checkout-session`
  - Requires authenticated user
  - Checks email verified status
  - Validates user not already pro
  - Creates Stripe session with userId metadata
  - Returns checkout URL

- `GET /api/user/profile`
  - Returns current user profile
  - Shows isPro status and stripeSubscriptionId

**Middleware**:
- `authMiddleware`: Validates JWT token from Authorization header

### 5. Webhook Handler Updated

#### `server/stripe-routes.ts` ✅
**Event: checkout.session.completed**
- Extracts userId from metadata
- **CRITICAL**: Updates users table:
  - Set `isPro = true`
  - Set `stripeSubscriptionId = subscription_id`
- Also creates subscriber record for subscription tracking
- Records payment intent for billing history
- Includes idempotency checks to prevent duplicate processing

**Middleware Order in `server/index.ts`** (Already Correct):
1. `setupCors()`
2. `registerStripeWebhook()` ← **Registers with express.raw() before JSON**
3. `setupBodyParsing()` ← **JSON parsing comes AFTER webhook**
4. Rest of middleware stack

This order is **critical** because webhook signature verification requires raw request body.

### 6. Frontend Auth Context Updated

#### `lib/auth-context.tsx` ✅
**New Features**:
- `token` state for JWT storage
- `setAuthToken()` function to store tokens from server
- `TOKEN_KEY` secure storage for JWT persistence
- Enhanced user type with all required fields

**Integration Points**:
- Stores JWT in secure storage (SecureStore on native, AsyncStorage on web)
- Load token on app startup
- Clear token on logout

### 7. Subscription Modal Updated

#### `components/SubscriptionModal.tsx` ✅
**Changes**:
- Import `useAuth` hook
- Check `isAuthenticated` and `token` before checkout
- Call `/api/create-checkout-session` with Bearer token
- Handle authentication errors with user-friendly messages
- Updated API endpoint from `/stripe/create-checkout-session` to `/api/create-checkout-session`

### 8. Dependencies Added

#### `package.json` ✅
Added server-side packages:
- `bcryptjs@^2.4.3`: Password hashing
- `jsonwebtoken@^9.1.2`: JWT token generation/verification
- `uuid@^10.4.0`: Unique token generation (UUIDs)
- `nodemailer@^6.9.7`: Email delivery via SMTP

## Complete User Flow

### Registration Flow
1. User fills registration form with username, email, password
2. Frontend calls `POST /api/register`
3. Server:
   - Validates input
   - Checks email/username uniqueness
   - Hashes password with bcrypt
   - Creates unverified user in database
   - Generates verification token (24-hour expiry)
   - Sends verification email via Gmail
   - Returns JWT token + user data
4. User receives verification email with link
5. User clicks link or manually enters token
6. Frontend calls `POST /api/verify-email`
7. Server marks user as verified

### Login Flow
1. User enters username and password
2. Frontend calls `POST /api/login`
3. Server:
   - Finds user by username
   - Verifies password with bcrypt
   - Generates JWT token
   - Returns token + user profile
4. Frontend stores token in secure storage
5. Token automatically loaded on app restart

### Subscription Flow
1. User authenticated with valid JWT token
2. User clicks "Subscribe" button
3. SubscriptionModal calls `POST /api/create-checkout-session` with token
4. Server:
   - Verifies JWT token
   - Checks user exists
   - Checks email is verified
   - Checks not already pro
   - Creates Stripe checkout session with userId in metadata
   - Returns checkout URL
5. Frontend opens Stripe checkout in browser
6. User enters payment details in Stripe
7. On successful payment, Stripe sends webhook to server
8. Webhook handler:
   - Verifies signature using raw body
   - Extracts userId from metadata
   - Updates users table: isPro=true, stripeSubscriptionId=subscription_id
   - Creates/updates subscriber record
   - Records payment intent
9. Frontend polls `/api/user/profile` to check updated isPro status
10. UI updates to show premium features

## Database Schema Verification

Users table must have these columns (verify with `SELECT column_name FROM information_schema.columns WHERE table_name='users'`):

```
- id (UUID, primary key)
- username (text, unique)
- password (text)
- email (text, unique)
- is_verified (boolean)
- is_pro (boolean)
- stripe_subscription_id (text, nullable)
- verification_token (text, nullable)
- verification_token_expiry (timestamp, nullable)
- verified_at (timestamp, nullable)
```

## Testing Checklist

### ✅ Pre-Flight Checks
- [ ] Install npm packages: `npm install`
- [ ] Verify .env has all 7 variables filled
- [ ] Test database connection: `npm run db:push` (creates migrations)
- [ ] Start server: `npm run server:dev`

### ✅ Email Verification Tests
- [ ] User can register with valid email
- [ ] Verification email arrives (check spam folder)
- [ ] User can verify email via token
- [ ] Verified status updates in database

### ✅ Authentication Tests
- [ ] JWT token generated on login/register
- [ ] Token stored in secure storage
- [ ] Token persists across app restarts (native only)
- [ ] Token sent in Authorization header for protected routes
- [ ] Expired token returns 401

### ✅ Subscription Tests
- [ ] Unverified user gets 403 error attempting checkout
- [ ] Already-pro user gets 400 error attempting checkout
- [ ] Verified user can create checkout session
- [ ] Stripe checkout opens successfully
- [ ] Test payment completes (use Stripe test cards)
- [ ] Webhook updates user isPro=true
- [ ] User profile reflects premium status

### ✅ Webhook Tests
- [ ] Listen to webhook in Stripe Dashboard
- [ ] Verify raw body signature verification succeeds
- [ ] Verify userId extracted correctly from metadata
- [ ] Verify users table updated with stripeSubscriptionId
- [ ] Verify subscribers table populated correctly

## Stripe Test Cards

Use these cards in the Stripe checkout for testing:

**Successful Payment**:
- Card: 4242 4242 4242 4242
- Expiry: Any future date
- CVC: Any 3 digits

**Failed Payment**:
- Card: 4000 0000 0000 0002

## Environment Variables Reference

```bash
# Database (get from Supabase)
DATABASE_URL="postgresql://[user]:[password]@[host]:5432/postgres"

# Email (Gmail with app password)
EMAIL_USER="your-email@gmail.com"
EMAIL_PASS="your-16-character-app-password"

# Stripe (from Stripe Dashboard)
STRIPE_PUBLISHABLE_KEY="pk_test_..."
STRIPE_SECRET_KEY="sk_test_..."
STRIPE_WEBHOOK_SECRET="whsec_..."

# Node environment
NODE_ENV="development"
```

## Important Notes

1. **Webhook Signature Verification**: The middleware order in `server/index.ts` is critical. Webhook handler MUST be registered before JSON body parser.

2. **Metadata Tracking**: Always include `userId` in Stripe session metadata so webhook knows which user to update.

3. **Email Delivery**: Verify Gmail SMTP credentials work:
   ```bash
   telnet smtp.gmail.com 587
   ```

4. **Token Expiry**: JWT tokens expire in 24 hours. Implement token refresh if needed for longer sessions.

5. **Database Migrations**: Run `npm run db:push` to sync schema with database.

6. **CORS**: Both localhost and Replit domains are allowed. Add your domain to `setupCors()` if needed.

## File Summary

**New Files**:
- `server/lib/stripe.ts` - Stripe initialization and helpers
- `server/lib/email.ts` - Email delivery service

**Modified Files**:
- `.env` - Added all credentials
- `package.json` - Added bcryptjs, jsonwebtoken, uuid, nodemailer
- `server/routes.ts` - Added 5 new endpoints (register, verify, login, checkout, profile)
- `server/stripe-routes.ts` - Updated webhook to also update users table with isPro status
- `shared/schema.ts` - Verified users table has all email/verification fields
- `lib/auth-context.tsx` - Added token state management
- `components/SubscriptionModal.tsx` - Updated to call new checkout endpoint with auth

**Unchanged but Important**:
- `server/index.ts` - Webhook middleware order already correct ✅
- `server/db.ts` - Drizzle configuration ready ✅

## Support & Troubleshooting

### Webhook not triggering?
- Check Stripe webhook endpoint configuration
- Verify `STRIPE_WEBHOOK_SECRET` is correct
- Look for webhook logs in Stripe Dashboard

### Email not sending?
- Verify Gmail app password (not regular password)
- Enable "Less secure apps" if using Gmail password
- Check server logs for transporter errors

### JWT token issues?
- Verify `JWT_SECRET` is set in `server/routes.ts` (defaults to dev secret)
- Change to environment variable in production
- Check token expiry: `jwt.decode(token)`

### isPro status not updating?
- Verify webhook event arrives (check Stripe Dashboard)
- Check user ID matches in metadata vs users table
- Verify database connection and write permissions

## Next Steps

1. **Install dependencies**: `npm install`
2. **Setup database**: `npm run db:push`
3. **Start server**: `npm run server:dev`
4. **Test registration flow** with real email
5. **Test payment** with Stripe test card
6. **Monitor webhook** in Stripe Dashboard for completion

---

**Status**: ✅ Implementation Complete - Ready for Testing
