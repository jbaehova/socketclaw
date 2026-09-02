# OpenAI Platform boundary

SocketClaw sends every model request directly to the OpenAI Platform. The
runtime boundary is intentionally narrow:

- Base URL: `https://api.openai.com/v1`
- Generation endpoint: `POST /responses`
- Access check: `GET /models/gpt-5.6-luna`
- Model: `gpt-5.6-luna`
- Secret: `OPENAI_API_KEY`
- Response contract: strict JSON Schema
- Storage: disabled for generated responses

There is no configurable base URL, provider router, alternate model, or model
fallback. If the OpenAI request fails, SocketClaw stores a redacted failure and
keeps local monitoring available.

## Reasoning policy

SocketClaw selects reasoning effort from the event severity:

| Event severity | Effort |
|---|---|
| `medium` and below | `medium` |
| `high` | `high` |
| `critical` | `high` |

This keeps ordinary analysis balanced while giving high-impact security events
more reasoning budget. The exact effort is stored with every investigation.

## Guardrails

Automated tests enforce the fixed endpoint, model ID, request schema, effort
policy, secret redaction, retry behavior, and absence of alternate provider
paths in runtime source and dependency declarations.

The model and API choices follow the official
[GPT-5.6 Luna model documentation](https://developers.openai.com/api/docs/models/gpt-5.6-luna)
and [OpenAI model guidance](https://developers.openai.com/api/docs/guides/latest-model).
