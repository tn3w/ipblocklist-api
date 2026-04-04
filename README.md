# IPBlocklist API

Minimal Rust API that loads [IPBlocklist](https://github.com/tn3w/IPBlocklist) binary data and serves IP threat lookups.

## Endpoints

### `GET /lookup/{ip}`

Returns detection data for an IP address.

```json
{
    "ip": "1.2.3.4",
    "max_score": 0.81,
    "top_category": "spam",
    "categories": ["malware", "spam"],
    "flags": ["is_spammer", "is_phishing"],
    "feeds": ["hphosts_psh", "hphosts_fsa"]
}
```

### `GET /health`

Returns `{"status":"ok","timestamp":...}` or `{"status":"loading"}`.

## Auto-Update

The blocklist refreshes from GitHub releases every 24 hours at runtime.

## Deploy to Railway

1. Push to GitHub
2. Connect repo in [Railway](https://railway.com)
3. Railway auto-detects the Dockerfile and deploys

The `PORT` env var is set automatically by Railway.

## Local Development

```sh
cargo run
# GET http://localhost:8080/lookup/1.2.3.4
```
