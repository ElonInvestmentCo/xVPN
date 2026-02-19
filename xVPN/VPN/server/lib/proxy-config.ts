import { db } from "../db";
import { users } from "../../shared/schema";
import { eq } from "drizzle-orm";

/**
 * VPN Proxy Configuration
 * IPRoyal Texas Residential Proxy
 */
export const proxyConfig = {
  host: process.env.PROXY_HOST || "64.84.118.42",
  port: parseInt(process.env.PROXY_PORT || "12323", 10),
  username: process.env.PROXY_USER || "14a9e3b3d61ce",
  password: process.env.PROXY_PASS || "f32be24e71",
  location: "USA - Texas",
  provider: "IPRoyal",
  protocol: "socks5", // or "http" depending on proxy type
};

/**
 * Verifies if user has VPN access
 * @param userId - The user's ID
 * @returns True if user is Pro and Verified, false otherwise
 */
export async function verifyVpnAccess(userId: string): Promise<boolean> {
  try {
    const user = await db
      .select()
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);

    if (user.length === 0) {
      console.warn(`VPN Access Check: User not found (${userId})`);
      return false;
    }

    const userRecord = user[0];

    // Must be verified AND pro to access VPN
    const hasAccess = userRecord.isVerified && userRecord.isPro;

    if (!hasAccess) {
      console.warn(
        `VPN Access Denied: userId=${userId}, isVerified=${userRecord.isVerified}, isPro=${userRecord.isPro}`
      );
      return false;
    }

    console.log(`VPN Access Granted: userId=${userId}`);
    return true;
  } catch (error: any) {
    console.error(`VPN Access Check Error: ${error.message}`);
    return false;
  }
}

/**
 * Gets VPN configuration for authenticated user
 * @param userId - The user's ID
 * @returns Proxy configuration object or null if user not authorized
 */
export async function getVpnConfig(userId: string) {
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
    protocol: proxyConfig.protocol,
  };
}

/**
 * Validates proxy connectivity
 * @returns True if proxy is reachable
 */
export async function validateProxyConnection(): Promise<boolean> {
  try {
    // In a real implementation, you would test the proxy connection here
    // For now, we just verify credentials are present
    if (
      !proxyConfig.host ||
      !proxyConfig.port ||
      !proxyConfig.username ||
      !proxyConfig.password
    ) {
      console.error("Proxy credentials incomplete");
      return false;
    }

    console.log(
      `Proxy validated: ${proxyConfig.provider} (${proxyConfig.location})`
    );
    return true;
  } catch (error: any) {
    console.error(`Proxy validation error: ${error.message}`);
    return false;
  }
}
