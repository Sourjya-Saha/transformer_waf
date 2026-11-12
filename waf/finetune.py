"""Adapt the frozen model to new benign traffic with LoRA (r=8, alpha=32, query+value projections).

    python finetune.py confirmed_benign.log [more logs...] [--epochs 60] [--model model] [--no-replay]

Only the adapters train (<1% of parameters, seconds on CPU); the base weights stay frozen. Output is
model/lora.pt, which Scorer loads automatically. Delete that file to roll back. Only feed traffic an
operator has CONFIRMED is benign: whatever goes in here is learned as normal, attacks included.
The threshold is not recomputed, so re-run evaluate.py after adapting.
"""
import argparse
import os
import random

import torch

import data
import model as M
import train


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--model", default="model")
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--no-replay", action="store_true", help="do not mix in the original training logs")
    a = ap.parse_args()
    torch.manual_seed(0)  # adapter init and dropout, so repeated runs give the same adapter

    S = M.Scorer(a.model)
    new = sorted(data.load_logs(a.logs))

    def _resolve_log(f):
        for candidate in [f, os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", f), os.path.join("waf", "data", f)]:
            if os.path.exists(candidate):
                return candidate
        return None

    replay_files = [p for p in (_resolve_log(f) for f in train.LOGS) if p]
    replay = [] if a.no_replay else sorted(data.load_logs(replay_files))
    random.Random(0).shuffle(replay)
    shapes = new + replay[: 2 * len(new)]  # new traffic + 2x as much old traffic, so old behaviour is not forgotten
    print(f"{len(new)} new shapes + {len(shapes) - len(new)} replayed")
    net = S.model
    if not any("lora_" in n for n, _ in net.named_parameters()):
        params = M.add_lora(net)
    else:  # already adapted before: keep training the same adapters
        params = [p for n, p in net.named_parameters() if "lora_" in n]
        for p in params:
            p.requires_grad = True
    net.to("cuda" if torch.cuda.is_available() else "cpu")  # after add_lora, so the new adapters move too
    print(f"trainable parameters: {sum(p.numel() for p in params)} of {sum(p.numel() for p in net.parameters())}")
    M.fit(net, M.encode(S.tok, shapes), a.epochs, lr=1e-3, bs=16)
    torch.save({k: v.cpu() for k, v in M.lora_state(net).items()}, os.path.join(a.model, "lora.pt"))
    print(f"saved {a.model}/lora.pt")


if __name__ == "__main__":
    main()
