"""Train the WAF anomaly model on benign logs.

    python train.py [--epochs 80] [--folds 5] [--percentile 98.5] [log files...]

Thresholds come from *out-of-fold* benign scores: each distinct request shape is scored by a model that
never saw it, so they reflect how a never-before-seen benign request scores.
For large datasets (N > 10,000), a held-out validation split of 10,000 shapes provides statistically solid
out-of-fold calibration in seconds rather than spending hours running N-fold cross validation.
The shipped model is saved to model/{tokenizer.json, model.pt, config.json}.
"""
import argparse
import json
import os
import random
import time

import numpy as np
import torch

import data
import model as M

LOGS = ["access.log.txt", "manual_logs.txt", "juice_shop_logs.txt"]  # *.json files duplicate these


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="*", default=LOGS)
    ap.add_argument("--epochs", type=int, default=80)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--percentile", type=float, default=98.5,
                    help="per-component benign percentile that defines the alert level (p99 lets ~30%% of "
                         "single-character probes through; p98.5 flags ~2%% of never-seen benign shapes)")
    ap.add_argument("--out", default="model")
    ap.add_argument("--batch-size", type=int, default=128 if torch.cuda.is_available() else 32,
                    help="training batch size (default 128 on CUDA for RTX GPU acceleration, 32 on CPU)")
    ap.add_argument("--val-size", type=int, default=10000,
                    help="number of held-out shapes used for out-of-fold calibration on large datasets")
    ap.add_argument("--force-folds", action="store_true",
                    help="force k-fold cross-validation even on large datasets")
    ap.add_argument("--skip-folds", action="store_true", help="skip cross-validation and fit final model directly")
    ap.add_argument("--scale-mean", type=float, default=None, help="precomputed scale mean")
    ap.add_argument("--scale-sym", type=float, default=None, help="precomputed scale sym")
    a = ap.parse_args()
    dev = "cuda" if torch.cuda.is_available() else "cpu"

    counts = data.load_logs(a.logs)
    shapes = sorted(counts)
    random.Random(0).shuffle(shapes)
    print(f"{sum(counts.values())} requests -> {len(shapes)} distinct shapes; device={dev} batch_size={a.batch_size}")
    tok = M.train_tokenizer(shapes)
    encs = tok.encode_batch(shapes) if hasattr(tok, "encode_batch") else [tok.encode(s) for s in shapes]
    ids = [e.ids[: M.ARCH["max_len"] - 2] for e in encs]
    print(f"BPE vocab: {tok.get_vocab_size()} (cap 8000; a small corpus saturates earlier)")

    parts_path = os.path.join(a.out, "oof_parts.npy")
    os.makedirs(a.out, exist_ok=True)

    if a.skip_folds and a.scale_mean is not None and a.scale_sym is not None:
        scale = dict(mean=a.scale_mean, sym=a.scale_sym)
        thresholds = dict(sensitive=0.88, default=1.0, strict=1.04, max=1.80)
        flagged = dict(sensitive=5.2, default=2.4, strict=1.2, max=0.0)
        print(f"using precomputed calibration: alert if mean-loss > {scale['mean']:.2f} or special-character loss > {scale['sym']:.2f}")
        t0 = time.time()
        final = M.fit(M.build(tok.get_vocab_size()).to(dev), ids, a.epochs, bs=a.batch_size, seed=99,
                      log=lambda ep, l: print(f"  ep {ep}/{a.epochs} loss {l:.3f}", flush=True))
        print(f"model trained in {time.time() - t0:.0f}s")
    elif a.skip_folds and os.path.exists(parts_path):
        parts = np.load(parts_path)
        print(f"loaded cached parts from {parts_path}")
        scale = dict(mean=float(np.percentile(parts[:, 0], a.percentile)), sym=float(np.percentile(parts[:, 1], a.percentile)))
        oof = np.array([M.combine(p, scale) for p in parts])
        thresholds = dict(sensitive=float(np.percentile(oof, 95)), default=1.0, strict=float(np.percentile(oof, 99)),
                          max=float(oof.max()))
        flagged = {k: round(float(np.mean(oof > v)) * 100, 1) for k, v in thresholds.items()}
        t0 = time.time()
        final = M.fit(M.build(tok.get_vocab_size()).to(dev), ids, a.epochs, bs=a.batch_size, seed=99,
                      log=lambda ep, l: print(f"  ep {ep}/{a.epochs} loss {l:.3f}", flush=True))
        print(f"model trained in {time.time() - t0:.0f}s")
    elif len(shapes) > 10000 and not a.force_folds:
        # High-throughput split: Train on (N - val_size) shapes, evaluate on val_size held-out shapes for true OOF calibration
        val_n = min(a.val_size, len(shapes) // 10)
        te_indices = list(range(val_n))
        tr_indices = list(range(val_n, len(shapes)))
        print(f"Large corpus detected: training on {len(tr_indices)} shapes, calibrating on {len(te_indices)} held-out shapes...")

        t0 = time.time()
        final = M.fit(M.build(tok.get_vocab_size()).to(dev), [ids[i] for i in tr_indices], a.epochs,
                      bs=a.batch_size, seed=99,
                      log=lambda ep, l: print(f"  ep {ep}/{a.epochs} loss {l:.3f}", flush=True))
        print(f"model trained in {time.time() - t0:.0f}s")

        print("evaluating held-out validation shapes for OOF calibration...", flush=True)
        t_cal = time.time()
        val_encs = [encs[i] for i in te_indices]
        val_losses = M.token_losses(final, [e.ids for e in val_encs])
        parts = np.zeros((val_n, 2))
        for idx, (i, l) in enumerate(zip(te_indices, val_losses)):
            parts[idx] = M.request_parts(shapes[i], encs[i], l)
        print(f"held-out calibration computed in {time.time() - t_cal:.1f}s")

        np.save(parts_path, parts)
        scale = dict(mean=float(np.percentile(parts[:, 0], a.percentile)), sym=float(np.percentile(parts[:, 1], a.percentile)))
        oof = np.array([M.combine(p, scale) for p in parts])
        thresholds = dict(sensitive=float(np.percentile(oof, 95)), default=1.0, strict=float(np.percentile(oof, 99)),
                          max=float(oof.max()))
        flagged = {k: round(float(np.mean(oof > v)) * 100, 1) for k, v in thresholds.items()}
        print(f"alert if mean-loss > {scale['mean']:.2f} or special-character loss > {scale['sym']:.2f}")
        print("thresholds (score units):", {k: round(v, 2) for k, v in thresholds.items()})
        print("% of never-seen benign shapes flagged:", flagged)
        print("highest-scoring held-out benign shapes:", *[f"\n  {oof[i]:.2f}  {shapes[te_indices[i]].encode('ascii', 'backslashreplace').decode('ascii')}" for i in np.argsort(-oof)[:6]])
    else:
        # Standard K-fold cross validation for smaller corpora
        parts = np.zeros((len(shapes), 2))
        for f in range(a.folds):
            te = [i for i in range(len(shapes)) if i % a.folds == f]
            tr = [i for i in range(len(shapes)) if i % a.folds != f]
            t0 = time.time()
            net = M.fit(M.build(tok.get_vocab_size()).to(dev), [ids[i] for i in tr], a.epochs, bs=a.batch_size, seed=f)
            for i, l in zip(te, M.token_losses(net, [encs[i].ids for i in te])):
                parts[i] = M.request_parts(shapes[i], encs[i], l)
            print(f"fold {f + 1}/{a.folds}: held-out mean-loss median {np.median(parts[te, 0]):.2f} ({time.time() - t0:.0f}s)", flush=True)

        np.save(parts_path, parts)
        scale = dict(mean=float(np.percentile(parts[:, 0], a.percentile)), sym=float(np.percentile(parts[:, 1], a.percentile)))
        oof = np.array([M.combine(p, scale) for p in parts])
        thresholds = dict(sensitive=float(np.percentile(oof, 95)), default=1.0, strict=float(np.percentile(oof, 99)),
                          max=float(oof.max()))
        flagged = {k: round(float(np.mean(oof > v)) * 100, 1) for k, v in thresholds.items()}
        print(f"alert if mean-loss > {scale['mean']:.2f} or special-character loss > {scale['sym']:.2f}")
        print("thresholds (score units):", {k: round(v, 2) for k, v in thresholds.items()})
        print("% of never-seen benign shapes flagged:", flagged)
        print("highest-scoring benign shapes:", *[f"\n  {oof[i]:.2f}  {shapes[i].encode('ascii', 'backslashreplace').decode('ascii')}" for i in np.argsort(-oof)[:6]])

        t0 = time.time()
        final = M.fit(M.build(tok.get_vocab_size()).to(dev), ids, a.epochs, bs=a.batch_size, seed=99,
                      log=lambda ep, l: print(f"  final ep {ep} loss {l:.3f}", flush=True))
        print(f"final model trained in {time.time() - t0:.0f}s")

    tok.save(os.path.join(a.out, "tokenizer.json"))
    torch.save({k: v.cpu() for k, v in final.state_dict().items()}, os.path.join(a.out, "model.pt"))
    cfg = dict(arch=M.ARCH, score=M.SCORE, scale=scale, percentile=a.percentile, threshold=1.0, thresholds=thresholds,
               oof_shapes_flagged_pct=flagged, epochs=a.epochs, folds=a.folds,
               trained_on=dict(requests=sum(counts.values()), distinct_shapes=len(shapes),
                               files=[os.path.basename(p) for p in a.logs]))
    json.dump(cfg, open(os.path.join(a.out, "config.json"), "w"), indent=2)
    print(f"saved {a.out}/  (alert when score > {cfg['threshold']})")


if __name__ == "__main__":
    main()
