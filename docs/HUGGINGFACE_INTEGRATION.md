# Hugging Face integration

ZeroDay's LLM Rakshak supports Hugging Face through the `huggingface` provider. It speaks the OpenAI-compatible Chat Completions protocol used by Hugging Face Inference Providers and can also target a dedicated Hugging Face Inference Endpoint (TGI) or a self-hosted OpenAI-compatible server.

## Supported paths

| Path | Provider | Endpoint |
|---|---|---|
| Hugging Face Inference Providers (router) | `huggingface` | Leave blank to use `https://router.huggingface.co/v1` |
| Dedicated Inference Endpoint / TGI | `huggingface` | Set the endpoint base URL |
| vLLM / Ollama / LM Studio / private gateway | `openai_compatible` or `custom` | Set the endpoint base URL |
| OpenAI-compatible cloud | `openai_compatible` | Set the endpoint base URL |

The default HF route is:

```text
POST https://router.huggingface.co/v1/chat/completions
Authorization: Bearer <HF_TOKEN>
Content-Type: application/json
```

If an endpoint is supplied, `/chat/completions` is appended when absent. User-supplied endpoints pass through the SSRF-safe client and require `LLMGUARD_ALLOW_PRIVATE_TARGETS=true` for private networks.

## 1. Create a token

1. Sign in to Hugging Face.
2. Open **Settings → Access Tokens**.
3. Create a fine-grained token with permission to call Inference Providers (or the specific Inference Endpoint).
4. Store the token in ZeroDay, not in client code.

Do not use a write/admin token for assessment. Use the minimum scope and rotate it if it is exposed.

## 2. Add the credential in ZeroDay

1. Open **Models & credentials**.
2. Choose **Hugging Face Inference Providers**.
3. Paste the token. Leave endpoint blank for the router.
4. Save. The key is encrypted with Fernet and only a masked preview is returned.

API equivalent:

```bash
curl -b cookies.txt -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -X PUT http://127.0.0.1:8000/api/credentials/huggingface \
  -d '{"api_key":"hf_...","endpoint":null}'
```

## 3. Create a model configuration

Use the exact model identifier accepted by the route. Examples (availability and naming change; check the Hugging Face model card and your account):

```json
{
  "name": "HF Llama 3.3 70B",
  "provider": "huggingface",
  "model": "meta-llama/Llama-3.3-70B-Instruct",
  "endpoint": null,
  "system_prompt": "You are a support assistant.",
  "params": {"temperature": 0.2, "max_tokens": 512},
  "credential_provider": "huggingface"
}
```

For a dedicated endpoint:

```json
{
  "name": "HF dedicated TGI",
  "provider": "huggingface",
  "model": "tgi",
  "endpoint": "https://<endpoint-id>.<region>.aws.endpoints.huggingface.cloud/v1",
  "params": {"temperature": 0.2, "max_tokens": 512},
  "credential_provider": "huggingface"
}
```

The model value is sent as the `model` field. For some dedicated TGI deployments the served model name is ignored or fixed; use the value documented by the endpoint.

## 4. Test the connection

Use **Test connection** or:

```bash
curl -b cookies.txt -H "X-CSRF-Token: $CSRF" -X POST \
  http://127.0.0.1:8000/api/models/<model_config_id>/test
```

The test sends a bounded request through the same provider adapter used by assessments. Common failures:

| Symptom | Likely cause |
|---|---|
| 401/403 | Token missing, revoked, or lacks Inference Providers permission |
| 404 | Model ID not served by the selected route/endpoint |
| 429 | Provider quota or concurrency limit |
| 400 model not supported | The model does not expose a chat-completions interface |
| Timeout | Cold start, endpoint scaling, or network policy |
| SSRF/private-address block | Endpoint resolves to a private address while private targets are disabled |

## 5. Tool calling and parameters

- The adapter sends OpenAI-style `tools` when a test needs tool-call observation. Whether the model honours them depends on the model and endpoint. If the provider rejects tools, the execution is recorded as an error, not as a passed test.
- `max_tokens` is sent (the HF router follows OpenAI-compatible semantics). Some native TGI endpoints expect `max_new_tokens`; use an OpenAI-compatible gateway or adjust the endpoint if yours is strict.
- Temperature is omitted when unset.
- Streaming is not used; responses are bounded by the assessment timeout and token limit.

## 6. Quotas and pacing

Hugging Face quotas vary by account and provider. If you see repeated 429s:

1. Set `LLMGUARD_PROVIDER_MIN_INTERVAL` to `60 / requests-per-minute` (for example `4` for 15 RPM).
2. Use **Low** intensity.
3. Reduce the module count or request budget.
4. Wait for the quota window; retries are bounded.

Pacing is process-wide. With multiple worker processes, divide the quota across workers.

## 7. Self-hosted alternatives

Hugging Face TGI, vLLM, Ollama and LM Studio all expose OpenAI-compatible chat endpoints. Prefer `openai_compatible` when the service is not the HF router:

```json
{
  "name": "Local vLLM",
  "provider": "openai_compatible",
  "model": "meta-llama/Llama-3.1-8B-Instruct",
  "endpoint": "http://127.0.0.1:8000/v1",
  "params": {"temperature": 0.1, "max_tokens": 512}
}
```

Set `LLMGUARD_ALLOW_PRIVATE_TARGETS=true` and `LLMGUARD_ALLOW_HTTP_TARGETS=true` only in a single-tenant/self-hosted deployment. Cloud metadata addresses remain blocked.

Ollama example:

```text
endpoint: http://127.0.0.1:11434/v1
model: llama3.1
```

vLLM example:

```text
endpoint: http://127.0.0.1:8001/v1
model: <served-model-name>
```

## 8. Security notes

- Treat model output as untrusted. The platform captures it as evidence and does not render or execute it.
- Do not put real secrets in the system prompt. The harness uses synthetic canaries, but the prompt is still stored/transmitted to the provider.
- Assessment evidence is redacted before storage and re-redacted for reports. Over-redaction is possible.
- Endpoint ownership is an attestation, not DNS/HTTP proof of control. Only test endpoints you own.
- Provider terms and data-retention policies apply to prompts sent during an assessment. Use a staging model and synthetic data where possible.
