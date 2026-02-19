# replit.md

## Overview

xVPN is a mobile VPN client application built with Expo (React Native), an Express proxy server, and a FastAPI (Python) backend. It offers a dark-themed UI for simulating VPN connectivity, featuring server selection across 50 global locations, live telemetry, connection management, a world map visualization, and various settings like protocol selection, kill switch, auto-connect, biometric lock, DNS leak protection, and ad blocker. The application also includes a premium subscription system. It simulates VPN connection states and network statistics rather than providing actual VPN tunneling.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend (Expo / React Native)

- **Framework**: Expo SDK 54 with React Native 0.81, utilizing the new architecture and React Compiler.
- **Routing**: File-based routing with `expo-router` v6, supporting typed routes and a tab-based layout with fade animations.
- **Authentication**: Login/Signup flow with `expo-secure-store` (SecureStore) for persistent sessions. Falls back to AsyncStorage on web. Users stay logged in until they sign out. Auth gate wraps the entire app.
- **Biometric Gate**: Uses `expo-local-authentication` for Face ID/fingerprint lock on app launch and resume. Shows a full-screen lock overlay until authenticated. Configurable via Settings.
- **State Management**: VPN connection state, client-side fingerprint shield settings, and server-side data fetching (using `@tanstack/react-query`) are managed through React Contexts and AsyncStorage.
- **UI Design**: Features a dark cyberpunk/futuristic theme with glass-morphism effects, animated elements (orbs, SVG visualizations), and guarded haptic feedback. Key components include `NoiseBackground`, `GlassCard`, `PowerButton`, `WorldMap`, and `LiveTelemetry`.
- **Animations**: `react-native-reanimated` v4 is used for smooth animations and transitions, including a full-screen "Radar Scanning" effect.
- **Fonts**: Custom Google Fonts: Space Grotesk and Orbitron.
- **Platform Support**: Supports iOS, Android, and Web, with platform-specific adaptations.

### Backend (FastAPI / Python)

- **Framework**: FastAPI on Python 3.11 with Uvicorn.
- **Authentication**: JWT-based system with bcrypt hashing for user registration, login, token refresh, and profile management. All VPN-related endpoints require authentication.
- **API Endpoints**: Comprehensive set of API endpoints for authentication, simulated VPN connection management, status updates, server listings, security checks, disconnection, obfuscation configuration, kill switch management, multi-hop VPN, fingerprint shield configuration, and a no-logs policy.
- **Database**: Uses SQLite via SQLAlchemy for User and ServerLog models. User profiles store preferences, subscription tier, and session stats. Server logs are purged every 5 minutes without identifying data.
- **Session Management**: In-memory tracking of active VPN connections and kill switch registry.
- **Kill Switch Engine**: Monitors heartbeats, auto-terminates inactive sessions, and engages network locks via simulated firewall rules.
- **Multi-Hop (Double VPN)**: Simulates routing traffic through two server nodes with dual encryption layers, offering pre-configured privacy-optimized routes.
- **Fingerprinting Shield**: Strips/normalizes identifying headers, spoofs canvas, WebGL, audio context, screen resolution, timezone, font enumeration, TCP OS fingerprint, TLS JA3 hash, and HTTP/2 SETTINGS.
- **Obfuscation Engine**: Includes residential proxy middleware (simulating routing through residential IPs) and stealth mode (wrapping WireGuard traffic in Shadowsocks, V2Ray VMess, or obfs4 to mimic HTTPS traffic).

### Express Proxy Server

- **Framework**: Express v5 with Node.js and TypeScript.
- **Proxy**: Proxies all `/api` routes to the FastAPI backend using `http-proxy-middleware`.
- **Stripe Routes**: Direct Express routes at `/stripe/*` for checkout sessions, webhooks, session verification, and revenue dashboard.
- **CORS**: Configured to allow Replit domains and localhost for development.
- **Static Serving**: Serves a pre-built Expo web bundle in production; otherwise, a landing page is displayed.

### Stripe Integration

- **SDK**: Stripe Node.js SDK for payment processing.
- **Plans**: Elite Stealth ($19.99/mo) and Annual Pass ($189/yr) subscription plans.
- **Checkout**: Creates Stripe Checkout Sessions via `/stripe/create-checkout-session`.
- **Webhooks**: Handles `checkout.session.completed`, `customer.subscription.updated/deleted`, and `invoice.payment_succeeded` at `/stripe/webhook`.
- **Revenue Dashboard**: Admin-only endpoint at `/stripe/revenue-dashboard` for viewing total funds, active subscriptions, plan breakdown, and recent payments (API only, no UI tab).
- **Database Sync**: Successful payments sync to `subscribers` and `payments` tables in PostgreSQL via Drizzle ORM.
- **Environment Variables**: `STRIPE_PUBLISHABLE_KEY`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`.

### Database (Drizzle ORM)

- **ORM**: Drizzle ORM configured for PostgreSQL, with schema defined in `shared/schema.ts` for `users`, `subscribers`, and `payments` tables.
- **Migrations**: Managed via a `./migrations` directory.
- **Connection**: `server/db.ts` provides the Drizzle database instance using `pg` pool.

### Build & Development

- **Dev mode**: Runs Expo dev server, Express proxy, and FastAPI concurrently.
- **Production build**: Expo web is statically built, and the Express server serves this build.

## External Dependencies

- **Database**: PostgreSQL via `pg` driver (configured for Drizzle ORM).
- **AsyncStorage**: `@react-native-async-storage/async-storage` for client-side persistence.
- **Expo Services**: Modules for haptics, image handling, gradients, blur effects, SVG, location, and web browser functionality.
- **Python**: FastAPI, Uvicorn, Pydantic.
- **Environment Variables**: `DATABASE_URL`, `REPLIT_DEV_DOMAIN`, `EXPO_PUBLIC_DOMAIN`, `REPLIT_DOMAINS`.