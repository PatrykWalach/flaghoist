import type {
  FlagSnapshot,
  FlagWebhookEvent,
  MemberWebhookEvent,
  StorageAdapter,
  WebhookEndpoint,
  WebhookEvent,
} from '@flaghoist/core'
import { MEMBER_WEBHOOK_EVENTS, WEBHOOK_EVENTS } from '@flaghoist/core'

/** Every event a webhook can subscribe to: flag events, and the opt-in member events. */
export const ALL_WEBHOOK_EVENTS: WebhookEvent[] = [...WEBHOOK_EVENTS, ...MEMBER_WEBHOOK_EVENTS]

// ---------------------------------------------------------------------------
// Webhook store (persistent when the adapter supports it, in-memory otherwise)
// ---------------------------------------------------------------------------

export interface WebhookStore {
  list(): Promise<WebhookEndpoint[]>
  get(id: string): Promise<WebhookEndpoint | null>
  put(id: string, webhook: WebhookEndpoint): Promise<void>
  delete(id: string): Promise<void>
}

export function createWebhookStore(storage?: StorageAdapter | null): WebhookStore {
  if (
    storage?.putWebhook &&
    storage?.getWebhook &&
    storage?.deleteWebhook &&
    storage?.listWebhooks
  ) {
    return {
      list: () => storage.listWebhooks!(),
      get: (id) => storage.getWebhook!(id),
      put: (id, w) => storage.putWebhook!(id, w),
      delete: (id) => storage.deleteWebhook!(id),
    }
  }

  const mem = new Map<string, WebhookEndpoint>()
  return {
    async list() {
      return [...mem.values()]
    },
    async get(id) {
      return mem.get(id) ?? null
    },
    async put(id, w) {
      mem.set(id, w)
    },
    async delete(id) {
      mem.delete(id)
    },
  }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export interface WebhookInput {
  url: string
  events?: WebhookEvent[]
  enabled?: boolean
}

const URL_MAX = 2048

export function validateWebhookInput(
  input: unknown,
): { ok: true; value: WebhookInput } | { ok: false; error: string } {
  if (!input || typeof input !== 'object') return { ok: false, error: 'Expected an object' }
  const obj = input as Record<string, unknown>

  if (typeof obj.url !== 'string' || !obj.url.trim()) {
    return { ok: false, error: 'url is required' }
  }
  const url = obj.url.trim()
  if (url.length > URL_MAX) return { ok: false, error: `url must be at most ${URL_MAX} characters` }

  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return { ok: false, error: 'url is not a valid URL' }
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { ok: false, error: 'url must use http or https' }
  }

  let events: WebhookEvent[] | undefined
  if (obj.events !== undefined) {
    if (!Array.isArray(obj.events)) return { ok: false, error: 'events must be an array' }
    for (const e of obj.events) {
      if (!ALL_WEBHOOK_EVENTS.includes(e as WebhookEvent)) {
        return { ok: false, error: `Unknown event: ${String(e)}` }
      }
    }
    events = obj.events as WebhookEvent[]
  }

  let enabled: boolean | undefined
  if (obj.enabled !== undefined) {
    if (typeof obj.enabled !== 'boolean') return { ok: false, error: 'enabled must be a boolean' }
    enabled = obj.enabled
  }

  return { ok: true, value: { url, events, enabled } }
}

// ---------------------------------------------------------------------------
// HMAC signing
// ---------------------------------------------------------------------------

export async function sign(secret: string, body: string): Promise<string> {
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(body))
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('')
  return hex
}

async function generateChangeId(change: string) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(change))

  const bytes = new DataView(hash)
  // Keep 53 bits so the result is an exact JavaScript integer.
  return Number(bytes.getBigUint64(0, false) & 0x1fffffffffffffn)
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export interface FlagWebhookPayload {
  event: FlagWebhookEvent
  timestamp: string
  flag: {
    key: string
    enabled: boolean
    rollout: { percentage: number }
    description: string
  }
  actor: string
  previous?: FlagSnapshot
  /** The environment the change happened in. Absent means the default environment. */
  environment?: string
}

/** A team change. Only sent to webhooks that list the member event. */
export interface MemberWebhookPayload {
  event: MemberWebhookEvent
  timestamp: string
  actor: string
  member: {
    /** Absent for `member.invited`: the account does not exist yet. */
    id?: string
    email: string
    role: string
    status?: string
    environmentRoles?: Record<string, string>
  }
  /** What changed from, on `member.role_changed`. */
  previous?: { role: string; environmentRoles?: Record<string, string> }
}

export type WebhookPayload = FlagWebhookPayload | MemberWebhookPayload

export interface WebhookPayloadSentryData {
  change_id: number //	A 64-bit idempotency token representing a unique change group.
  action: 'created' | 'updated' | 'deleted'
  created_at: string // e.g. "2024-12-12T00:02:00+00:00";
  created_by: {
    id: string // e.g. "first.last@company.com";
    type: 'email' | 'id' | 'name'
  }
  flag: string // e.g. "hello.world";
}

export interface WebhookPayloadSentry {
  data: [WebhookPayloadSentryData]
  meta: { version: 1 }
}

export async function dispatchWebhooks(
  store: WebhookStore,
  event: WebhookEvent,
  payload: WebhookPayload,
): Promise<void> {
  const hooks = await store.list()
  const active = hooks.filter((h) => h.enabled && h.events.includes(event))
  if (active.length === 0) return

  const deliveries = active.map(async (hook) => {
    try {
      await dispatchWebhook(hook, event, payload)
    } catch {
      // fire-and-forget: log failures but do not block the caller
    }
  })

  await Promise.allSettled(deliveries)
}

export async function dispatchWebhook(
  hook: WebhookEndpoint,
  event: WebhookEvent,
  payload: WebhookPayload,
): Promise<Response> {
  const format = /\/organizations\/.+\/flags\/hooks\/provider\/generic\/$/.test(hook.url)
    ? 'sentry'
    : 'flaghoist'

  switch (format) {
    case 'sentry': {
      switch (payload.event) {
        case 'member.removed':
        case 'member.joined':
        case 'member.disabled':
        case 'member.enabled':
        case 'member.invited':
        case 'member.role_changed': {
          throw new Error(
            'When setting up the hook for ' +
              hook.url +
              ' event type of ' +
              payload.event +
              " was selected but it's not supported by Sentry",
          )
        }

        case 'flag.deleted':
        case 'flag.restored':
        case 'flag.updated':
        case 'flag.created':
        case 'flag.archived': {
          const eventData = {
            action: (
              {
                'flag.deleted': 'deleted',
                'flag.restored': 'created',
                'flag.updated': 'updated',
                'flag.created': 'created',
                'flag.archived': 'deleted',
              } as const
            )[payload.event],
            created_at: payload.timestamp,
            created_by: {
              type: 'name',
              id: payload.actor,
            },
            flag: payload.flag.key,
          } satisfies Omit<WebhookPayloadSentryData, 'change_id'>
          const payloadSentry: WebhookPayloadSentry = {
            meta: { version: 1 },
            data: [
              {
                change_id: await generateChangeId(JSON.stringify(eventData)),
                ...eventData,
              },
            ],
          }

          const body = JSON.stringify(payloadSentry)

          const signature = await sign(hook.secret, body)
          return await fetch(hook.url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Sentry-Signature': signature,
            },
            body,
            signal: AbortSignal.timeout(10_000),
          })
        }
      }
    }
    case 'flaghoist': {
      const body = JSON.stringify(payload)

      const signature = await sign(hook.secret, body)
      return await fetch(hook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Flaghoist-Event': event,
          'X-Flaghoist-Signature': `sha256=${signature}`,
          'X-Flaghoist-Webhook-Id': hook.id,
        },
        body,
        signal: AbortSignal.timeout(10_000),
      })
    }
  }
}

// ---------------------------------------------------------------------------
// ID + secret generation
// ---------------------------------------------------------------------------

export function generateId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 16)
}

export function generateSecret(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}
