/**
 * Error logging service stub for Sentry integration
 * In production, connects to Sentry or your error tracking service
 */

interface ErrorContext {
  userId?: string;
  endpoint?: string;
  method?: string;
  body?: any;
  query?: any;
}

export class ErrorLogger {
  private isDevelopment = process.env.NODE_ENV !== 'production';

  /**
   * Log an error with optional context
   */
  logError(error: Error | string, context?: ErrorContext) {
    const timestamp = new Date().toISOString();
    const message = typeof error === 'string' ? error : error.message;
    const stack = typeof error !== 'string' ? error.stack : undefined;

    const logEntry = {
      timestamp,
      level: 'error',
      message,
      stack,
      context,
    };

    // Log to console in development
    if (this.isDevelopment) {
      console.error('[ERROR]', JSON.stringify(logEntry, null, 2));
    }

    // In production, send to Sentry:
    // Sentry.captureException(error, { contexts: { http: context } });

    // For now, just ensure it's logged
    console.error('[PROD_ERROR]', message);
  }

  /**
   * Log authentication failures
   */
  logAuthFailure(endpoint: string, reason: string, userId?: string) {
    this.logError(`Auth failure: ${reason}`, {
      endpoint,
      userId,
    });
  }

  /**
   * Log payment/subscription errors
   */
  logPaymentError(error: Error | string, userId: string, sessionId?: string) {
    this.logError(error, {
      userId,
      endpoint: '/api/webhooks/stripe',
      context: { sessionId } as any,
    });
  }

  /**
   * Log VPN connection errors
   */
  logVpnError(error: Error | string, userId: string) {
    this.logError(error, {
      userId,
      endpoint: '/api/vpn/config',
    });
  }
}

export const errorLogger = new ErrorLogger();
