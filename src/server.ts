import { Hono } from "hono"
import { cors } from "hono/cors"
import { logger } from "hono/logger"

import { completionRoutes } from "./routes/chat-completions/route"
import { embeddingRoutes } from "./routes/embeddings/route"
import { messageRoutes } from "./routes/messages/route"
import { modelRoutes } from "./routes/models/route"
import { tokenRoute } from "./routes/token/route"
import { usageRoute } from "./routes/usage/route"
import { apiKeyAuth } from "./lib/api-key-auth"
import { state } from "./lib/state"
import { setupCopilotToken } from "./lib/token"
import { cacheModels } from "./lib/utils"

export const server = new Hono()

server.use(logger())
server.use(cors())

// API Key authentication middleware
server.use(apiKeyAuth)

server.get("/", (c) => c.text("Server running"))
server.get("/health", (c) => c.json({ status: "ok" }))

// Internal endpoint for dashboard to update GitHub token
server.post("/internal/update-token", async (c) => {
  try {
    const body = await c.req.json() as { github_token?: string }
    if (body.github_token) {
      state.githubToken = body.github_token
      await setupCopilotToken()
      await cacheModels()
      return c.json({ 
        success: true, 
        message: "Token updated and models cached",
        models_count: state.models?.data?.length || 0
      })
    }
    return c.json({ error: "No token provided" }, 400)
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error)
    return c.json({ error: "Failed to update token", details: errMsg }, 500)
  }
})

server.route("/chat/completions", completionRoutes)
server.route("/models", modelRoutes)
server.route("/embeddings", embeddingRoutes)
server.route("/usage", usageRoute)
server.route("/token", tokenRoute)

// Compatibility with tools that expect v1/ prefix
server.route("/v1/chat/completions", completionRoutes)
server.route("/v1/models", modelRoutes)
server.route("/v1/embeddings", embeddingRoutes)

// Anthropic compatible endpoints
server.route("/v1/messages", messageRoutes)
