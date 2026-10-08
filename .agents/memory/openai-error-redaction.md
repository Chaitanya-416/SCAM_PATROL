---
name: OpenAI error redaction
description: Keep provider errors from exposing partial credentials in ScamPatrol logs.
---

OpenAI SDK errors can include a prefix of the API key in an authentication failure message. Do not log raw SDK error objects or provider messages.

**Why:** an invalid-key response included a credential prefix in the exception text.

**How to apply:** keep the key server-side and log only sanitized error status/type at the API boundary. Never inspect or print the secret value.
