# Transformer WAF: Juice Shop anomaly model

A signature-free WAF model trained **only on benign traffic** from one site (OWASP Juice Shop). It learns
what normal requests look like and flags anything that does not fit, plus a tamper-evident audit log.
Pipeline: log normalisation -> BPE tokenizer -> BERT-style transformer -> anomaly score -> hash-chained log.

## Run it

```bash
pip install -r requirements.txt           # CPU torch is enough to run the model

python waf.py check "GET /rest/products/search?q=' OR 1=1--" --explain
python waf.py check "GET /rest/products/search?q=apple"
python waf.py scan access.log.txt         # score a whole log; flagged requests go to the audit chain
python waf.py serve --port 8080 --block   # HTTP service for nginx (omit --block = monitor only)
python chain.py verify waf_chain.jsonl    # prove the audit log was not edited
```

Score meaning: **1.0 = alert level**. Normal requests score about 0.1-0.2. `--explain` shows which tokens
drove the score. Presets: `--threshold sensitive | default | strict | max` (or any number).
Inputs it understands: the nginx key=value log, the combined-style manual log, and the Juice Shop proxy log.
Single request on CPU: ~22 ms.

## Results (measured, `python evaluate.py --split final|test`)

Attacks were **written by me** (SQLi, XSS, path traversal, command injection, template/log4j/SSRF-style,
recon paths, scanner user-agents) and injected into real Juice Shop endpoints, plain and double URL-encoded.
The training logs contain no attacks, so there is nothing else to measure detection on.

| Attack set | n | Detected at default | sqli | xss | traversal | cmdi | other | recon | scanner UA |
|---|---|---|---|---|---|---|---|---|---|
| **FINAL** (written after all design decisions) | 137 | **97.8%** | 100% | 100% | 100% | 100% | 100% | 100% | 67% |
| TEST (used while debugging; one normaliser bug fixed from it) | 154 | 96.8% | 100% | 100% | 100% | 83% | 100% | 93% | 88% |

Detection at the `sensitive` preset is 100% (FINAL) / 98% (TEST); at `strict` 96% / 89%.

False positives, the number that matters most for a demo:

| Benign traffic | Alerts at default |
|---|---|
| The 21,541 logged requests (seen by training) | **0** |
| 73 legitimate requests that are **not** in the logs (new search words, new endpoints, new images) | **11%** (strict: 5.5%, sensitive: 23%) |
| 5 "hard" legitimate requests (apostrophe, brackets, `&`, passwords with symbols, long free text) | **100%** |
| Never-seen benign request shapes under cross-validation (how the threshold was set) | 2.1% |

## Read this before you present it

1. **POST bodies are invisible.** The logs record only method, URL, user-agent and referer. Juice Shop's
   best-known SQLi (the login email field) is in a JSON body, so this model cannot see it. To cover it, log
   `$request_body` in nginx, collect benign traffic, retrain.
2. **It learned one browsing session**: 329 distinct request shapes (21,541 requests, mostly repeats, some
   of it the developer's own curl/PowerShell tests). Anything legitimate it has never seen (a new endpoint, an
   unusual search term, free text, a password with symbols) will alert until you adapt it (see LoRA below).
   Expect these false alarms in a live demo.
3. **The 97.8% is optimistic.** The attacks are my own payloads, not real attacker traffic or a public
   benchmark (e.g. CSIC 2010 was not run). Evasions that avoid special characters and look like a normal
   value are weak spots: `%250aid` (a newline plus `id`, and `id` is a legal `fields=` value) scores 0.35.
4. Scanner detection relies on the user-agent being unusual. Wget, okhttp, Java and WPScan slip under the
   default threshold, and any scanner that sends a Chrome user-agent is not caught by that signal.
5. **The audit chain is a single-file hash chain, not a decentralised blockchain.** It detects edits and
   deletions in the middle. Someone with write access can rebuild the whole file, and cutting entries off the
   end is undetectable unless you record the head hash elsewhere (`chain.py verify` prints it).
6. The nginx snippets below were not run against a real nginx here. `waf.py serve` was tested with direct
   HTTP calls (benign -> 204, attacks -> 403 with `--block`).

## Where this differs from the proposal PDF (and why)

| Proposal | Built | Reason |
|---|---|---|
| Autoencoder, reconstruction loss | **Masked** autoencoder: hide tokens, reconstruct from context | A plain autoencoder with full self-attention copies its input, so every request scores ~0 |
| Replace values with `PARAM` | Replace only ids, tokens, dates, emails, build hashes; keep other values | `q=PARAM` makes `q=' OR 1=1` identical to `q=apple`; the model could never see an injection |
| 8K BPE vocab | Byte-level BPE, cap 8000, **993 learned** | 329 distinct shapes saturate the vocabulary; every byte is representable, nothing is `[UNK]` |
| Score = mean cross-entropy, threshold at p99 | Score = max(mean loss, worst special-character loss), each scaled by its own benign 98.5th percentile | The mean alone detects 0.4% of single-character probes like `q='` (one odd token among ~24). The proposal's p99 also lets ~30% of them through |
| d=256, 6 layers, 8 heads, ff=1024, max_len 512 | Same, max_len 256 (longer requests are scored in windows) | Requests are at most ~60 tokens here |
| LoRA r=8, alpha=32 on query+value | Same, written by hand (no PEFT dependency) | 49,152 of 5.3M parameters (0.9%) train |
| Decentralised blockchain | Local SHA-256 hash chain | See limit 5 |

Normalisation (`data.py`) decodes percent-encoding up to 3 rounds, lower-cases, collapses whitespace
(keeping a leading newline), and masks the dynamic parts of this site: numeric ids, mixed letter/digit tokens,
dates, emails, hex order ids, SPA bundle hashes, user upload file names.

## Keep it current: LoRA adaptation

```bash
python finetune.py confirmed_benign.log     # operator-confirmed benign traffic ONLY; writes model/lora.pt
rm model/lora.pt                            # roll back
python demo_lora.py                         # reproduces the numbers below on a copy of the model
```
`finetune.py` mixes in 2x as much old traffic so the model does not forget it; that replay needs the three
training logs in the working directory (they are not in the release zip). Without them it adapts on the new
traffic alone.
Demo: adapting on 39 legitimate unseen requests cut false positives on 39 *different* legitimate requests
from 17.9% to 10.3%, with attack detection unchanged (97.3%). Small sample; treat as indicative. Whatever you
feed in is learned as normal, so never feed it unreviewed traffic. The threshold is not recalibrated.

## nginx (untested here)

Monitor mode, asynchronous so legitimate traffic is never delayed:
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
Blocking mode: run `waf.py serve --block` and replace `mirror ...;` with `auth_request /_waf;` (adds ~20 ms
per request, and a flagged request gets 403).

## Retrain

```bash
python train.py access.log.txt manual_logs.txt juice_shop_logs.txt     # ~5 min on an RTX 3060
```
5-fold cross-validation over the distinct request shapes sets the thresholds (every shape is scored by a
model that never saw it), then the shipped model is trained on all of them. CPU-only training works but is
slow (estimated about an hour, not measured). The `.json` logs duplicate the `.txt` ones and are ignored.

## Files

`data.py` parsing + normalisation, `model.py` tokenizer / transformer / LoRA / scorer, `train.py`,
`finetune.py`, `waf.py` (CLI + service), `chain.py` (audit log), `attacks.py` + `evaluate.py` (synthetic
evaluation), `demo_lora.py`, `model/` (weights, tokenizer, thresholds, training log), and
`INTEGRATION.md` (one-page guide for whoever builds the nginx layer or interface).
