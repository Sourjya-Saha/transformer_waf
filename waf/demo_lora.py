"""Reproduce the LoRA claim on a COPY of the model (model/ is not touched):

  adapt on half of the legitimate requests that are absent from the training logs, then check
  (a) the OTHER half: false positives should fall, (b) attack detection: should not.

    python demo_lora.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

import numpy as np

import attacks
from model import Scorer


def log_line(uri):
    return (f'172.17.0.1 - [2026-10-24T10:00:00+00:00] "GET {uri.replace(" ", "%20")} HTTP/1.1" 200 1 '
            f'"http://localhost/" "Mozilla/5.0 (Windows NT 10.0)" rt=0.01')


def main():
    benign = [u for u, _ in attacks.benign_novel(final=True)] + [u for u, _ in attacks.benign_novel(hard=True)]
    adapt, held = benign[::2], benign[1::2]
    atk = [n for s in ("test", "final") for _, _, n in attacks.attack_set(s)]
    work = tempfile.mkdtemp()
    shutil.copytree("model", os.path.join(work, "model"))
    log = os.path.join(work, "confirmed_benign.log")
    open(log, "w").write("\n".join(map(log_line, adapt)) + "\n")

    def measure():
        S = Scorer(os.path.join(work, "model"))
        fp = np.array(S.score([attacks._mk(u) for u in held])) > S.threshold
        det = np.array(S.score(atk)) > S.threshold
        return fp.mean() * 100, det.mean() * 100

    fp0, det0 = measure()
    subprocess.run([sys.executable, "finetune.py", log, "--model", os.path.join(work, "model")], check=True)
    fp1, det1 = measure()
    print(f"\nadapted on {len(adapt)} confirmed-benign requests; evaluated on {len(held)} DIFFERENT benign requests "
          f"and {len(atk)} attacks")
    print(f"  false positives on held-out benign: {fp0:5.1f}% -> {fp1:5.1f}%")
    print(f"  attack detection (TEST+FINAL):      {det0:5.1f}% -> {det1:5.1f}%")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
