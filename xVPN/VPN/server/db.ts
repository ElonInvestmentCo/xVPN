import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "../shared/schema";

// Production-ready connection pool with health checks
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,                    // Max simultaneous connections
  idleTimeoutMillis: 30000,   // Close idle connections after 30s
  connectionTimeoutMillis: 2000, // 2s timeout for new connections
  statement_timeout: 30000,   // 30s query timeout
});

// Pool error handling
pool.on('error', (err) => {
  console.error('Unexpected database pool error:', err);
  // In production, send to error tracking service
});

pool.on('connect', () => {
  console.log('[DB] New connection established');
});

pool.on('remove', () => {
  console.log('[DB] Connection removed from pool');
});

// Health check function
export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    const result = await pool.query('SELECT NOW()');
    return !!result.rows[0];
  } catch (error) {
    console.error('[DB] Health check failed:', error);
    return false;
  }
}

export const db = drizzle(pool, { schema });
