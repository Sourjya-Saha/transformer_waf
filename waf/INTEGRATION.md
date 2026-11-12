# Integration guide (nginx layer / interface)

The model runs as a small HTTP service. nginx asks it about each request; it answers allow or block and
writes flagged requests to a tamper-evident log. Full background: `README.md`.

## 1. Run the service

```bash
pip install -r requirements.txt
python waf.py serve --host 127.0.0.1 --port 8080            # monitor only: always answers 204, logs alerts
python waf.py serve --host 127.0.0.1 --port 8080 --block    # answers 403 for flagged requests
```

Use `--host 0.0.0.0` only if nginx is in another container, and only on an internal network (no authentication).
Run **one process** (threads are fine): the audit chain is only locked within a process.

## 2. Endpoints

| Endpoint | Input | Output |
|---|---|---|
| `GET/POST/... /check` | headers `X-Original-Method`, `X-Original-URI`, `User-Agent`, `Referer`, `X-Real-IP` | `204` allow, `403` block (block mode and flagged) |
| `POST /score` | JSON `{"method","uri","user_agent","referer","client_ip"}` (`uri` required) | JSON `{"score","threshold","flagged","normalized","tokens"}`; `tokens` = top 8 `[text, loss]` |

- Score **1.0 = alert**. Normal traffic is about 0.1 to 0.2.
- Pass nginx's `$request_uri` (raw). `$uri` is already decoded and changes what the model sees.
- Both endpoints append flagged requests to `waf_chain.jsonl`, including test traffic sent to `/score`.

## 3. nginx (not tested against a real nginx)

Monitor mode, asynchronous, never delays users, fails open if the service is down:
```nginx
location / {
    mirror /_waf;
    mirror_request_body off;
    proxy_pass http://juice:3000;
}
location = /_waf {
    internal;
    proxy_pass http://127.0.0.1:8080/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Original-URI    $request_uri;
    proxy_set_header X-Real-IP         $remote_addr;
}
```
Block mode: start the service with `--block` and replace `mirror /_waf;` and `mirror_request_body off;`
with `auth_request /_waf;`. Each request then waits about 20 ms for the answer. If the service is down nginx
returns 500 to users unless you add an `error_page` fallback.

## 4. Audit log

`waf_chain.jsonl`: one JSON object per line with `index, ts, ip, request, score, decision, prev_hash, hash`.
An interface can tail this file. Check integrity with `python chain.py verify waf_chain.jsonl`
(exit code 0 = intact, 1 = tampered; prints the break position).

## 5. Quick test

```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Original-URI: /rest/products/search?q=%27%20OR%201%3D1--" http://127.0.0.1:8080/check
```
Expect `403` in block mode. With `q=apple` expect `204`.

## Known gaps

No `/health`, `/events` or `/verify` endpoints. `serve` uses Flask's development server and has not been
load-tested (about 22 ms per request on CPU). POST bodies are not inspected.
