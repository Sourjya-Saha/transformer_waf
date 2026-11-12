"""Evaluate a trained model on traffic it was never trained on.   python evaluate.py [--model model] [--split test]

Reports detection rate per attack category at the default threshold (* column; other presets for comparison), the
false-positive rate on benign requests that are NOT in the training logs, and per-request latency.
"""
import argparse
import os
import time
from collections import defaultdict

import numpy as np
from sklearn.metrics import roc_auc_score

import attacks
import data
import train
from model import Scorer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="model")
    ap.add_argument("--split", default="test", choices=["dev", "test", "final"])
    ap.add_argument("--misses", type=int, default=12)
    a = ap.parse_args()
    S = Scorer(a.model)
    ths = {k + ("*" if k == "default" else ""): S.cfg["thresholds"][k] for k in ("sensitive", "default", "strict", "max")}

    atk = attacks.attack_set(a.split)
    a_s = np.array(S.score([n for _, _, n in atk]))
    cats = np.array([c for c, _, _ in atk])
    ben = attacks.benign_novel(final=a.split == "final")
    b_s = np.array(S.score([n for _, n in ben]))
    hard = attacks.benign_novel(hard=True)
    h_s = np.array(S.score([n for _, n in hard]))
    logs = [p for p in train.LOGS if os.path.exists(p)]  # the training logs are not shipped with the model
    counts = data.load_logs(logs)
    shapes = list(counts)
    l_s = np.array(S.score(shapes)) if shapes else np.zeros(0)
    w = np.array([counts[s] for s in shapes])

    print(f"\nthresholds: " + ", ".join(f"{k}={v:.2f}" for k, v in ths.items()))
    print(f"\n== detection on {a.split.upper()} attacks ({len(atk)} requests; payload families never used for training) ==")
    print(f"{'category':<12}{'n':>5}" + "".join(f"{k:>16}" for k in ths) + "   median score")
    for c in sorted(set(cats)):
        m = cats == c
        print(f"{c:<12}{m.sum():>5}" + "".join(f"{100 * (a_s[m] > t).mean():>15.1f}%" for t in ths.values()) + f"   {np.median(a_s[m]):.1f}")
    print(f"{'ALL':<12}{len(atk):>5}" + "".join(f"{100 * (a_s > t).mean():>15.1f}%" for t in ths.values()))

    print("\n== false positives (benign) ==")
    print(f"{'set':<44}{'n':>6}" + "".join(f"{k:>16}" for k in ths))
    rows = [("novel benign (valid, not in logs)", b_s, None), ("hard benign (quotes/passwords/free text)", h_s, None)]
    if len(l_s):
        rows += [("training-log shapes, unweighted (SEEN)", l_s, None), ("training-log requests, by frequency (SEEN)", l_s, w)]
    for name, s, wt in rows:
        n = len(s) if wt is None else int(wt.sum())
        fp = [(np.average(s > t, weights=wt) * 100) for t in ths.values()]
        print(f"{name:<44}{n:>6}" + "".join(f"{f:>15.1f}%" for f in fp))
    auc = roc_auc_score([1] * len(a_s) + [0] * len(b_s), np.r_[a_s, b_s])
    print(f"\nROC-AUC attacks vs novel benign: {auc:.3f}   (benign median {np.median(b_s):.2f}, attack median {np.median(a_s):.2f})")

    miss = [(s, atk[i][0], atk[i][1]) for i, s in enumerate(a_s) if s <= S.threshold]
    print(f"\nmissed at shipped threshold: {len(miss)}/{len(atk)}")
    for s, c, u in sorted(miss)[: a.misses]:
        print(f"  {s:5.2f} {c:<10} {u[:110]}")
    fps = [(s, u) for (u, _), s in zip(ben + hard, np.r_[b_s, h_s]) if s > S.threshold]
    print(f"\nbenign flagged at shipped threshold: {len(fps)}/{len(ben) + len(hard)}")
    for s, u in sorted(fps, reverse=True):
        print(f"  {s:5.2f} {u[:110]}")

    one = [n for _, _, n in atk[:60]]
    t0 = time.perf_counter()
    for n in one:
        S.score([n])
    print(f"\nlatency: {(time.perf_counter() - t0) / len(one) * 1000:.1f} ms/request (single request, {next(S.model.parameters()).device})")


if __name__ == "__main__":
    main()
