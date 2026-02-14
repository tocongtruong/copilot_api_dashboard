import { createMiddleware } from "hono/factory"
import type { Context, Next } from "hono"
import consola from "consola"

const DASHBOARD_URL = process.env.DASHBOARD_URL || "http://localhost:3000"
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || "internal-secret"
const ENABLE_AUTH = process.env.ENABLE_API_AUTH !== "false"

// Fire-and-forget request logging to dashboard
function logRequest(apiKey: string, endpoint: string, method: string, statusCode: number, ip: string, responseTimeMs: number) {
  fetch(`${DASHBOARD_URL}/api/log-request`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Internal-Secret": INTERNAL_SECRET,
    },
    body: JSON.stringify({
      api_key: apiKey,
      endpoint,
      method,
      status_code: statusCode,
      ip,
      response_time_ms: responseTimeMs,
    }),
  }).catch(() => { /* ignore logging failures */ })
}

// Cache for validated keys to reduce dashboard calls
const keyValidationCache = new Map<
  string,
  { valid: boolean; expiresAt: number; keyId?: string }
>()

const CACHE_TTL_MS = 60_000 // Cache validation results for 60 seconds

export const apiKeyAuth = createMiddleware(async (c: Context, next: Next) => {
  // Skip auth if disabled
  if (!ENABLE_AUTH) {
    return next()
  }

  // Skip auth for health check and root
  const path = c.req.path
  if (path === "/" || path === "/health") {
    return next()
  }

  // Skip auth for internal endpoints
  if (path.startsWith("/internal/")) {
    const secret = c.req.header("X-Internal-Secret")
    if (secret !== INTERNAL_SECRET) {
      return c.json({ error: "Forbidden" }, 403)
    }
    return next()
  }

  // Extract API key from Authorization header
  const authHeader = c.req.header("Authorization")
  if (!authHeader) {
    return c.json(
      { error: "Missing Authorization header. Use: Authorization: Bearer YOUR_API_KEY" },
      401,
    )
  }

  const apiKey = authHeader.replace("Bearer ", "").trim()
  const startTime = Date.now()
  const clientIp = c.req.header("x-forwarded-for") || c.req.header("x-real-ip") || ""

  if (!apiKey || apiKey === "dummy") {
    // Allow "dummy" token for backward compatibility
    await next()
    const elapsed = Date.now() - startTime
    logRequest("dummy", path, c.req.method, c.res.status, clientIp, elapsed)
    return
  }

  // Check cache first
  const cached = keyValidationCache.get(apiKey)
  if (cached && cached.expiresAt > Date.now()) {
    if (!cached.valid) {
      return c.json({ error: "Invalid API key" }, 401)
    }
    await next()
    const elapsed = Date.now() - startTime
    logRequest(apiKey, path, c.req.method, c.res.status, clientIp, elapsed)
    return
  }

  // Validate with dashboard
  try {
    const response = await fetch(`${DASHBOARD_URL}/api/validate-key`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": INTERNAL_SECRET,
      },
      body: JSON.stringify({
        api_key: apiKey,
        endpoint: path,
        method: c.req.method,
        ip: c.req.header("x-forwarded-for") || c.req.header("x-real-ip") || "",
      }),
    })

    const result = (await response.json()) as {
      valid: boolean
      error?: string
      key_id?: string
    }

    // Cache the result
    keyValidationCache.set(apiKey, {
      valid: result.valid,
      expiresAt: Date.now() + CACHE_TTL_MS,
      keyId: result.key_id,
    })

    if (!result.valid) {
      return c.json({ error: result.error || "Invalid API key" }, 401)
    }

    await next()
    const elapsed = Date.now() - startTime
    logRequest(apiKey, path, c.req.method, c.res.status, clientIp, elapsed)
    return
  } catch (error) {
    consola.warn(
      "Failed to validate API key with dashboard, allowing request:",
      error,
    )
    // If dashboard is unreachable, allow the request (fail-open for availability)
    return next()
  }
})

// Clean up expired cache entries periodically
setInterval(() => {
  const now = Date.now()
  for (const [key, value] of keyValidationCache.entries()) {
    if (value.expiresAt < now) {
      keyValidationCache.delete(key)
    }
  }
}, 300_000) // Clean every 5 minutes
