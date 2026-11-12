"""BPE tokenizer + BERT-style transformer autoencoder + anomaly scorer + LoRA adapters.

A plain autoencoder with full self-attention learns to copy its input (loss ~0 for everything, attacks
included). So it is trained as a *masked* autoencoder: hide tokens, reconstruct them from the rest of the
request. A request is scored by hiding every token once (K interleaved passes); the anomaly score is the mean
per-token cross-entropy, i.e. the reconstruction loss from the proposal.
"""
import json
import math
import os

import torch
import torch.nn as nn
import torch.nn.functional as F
from tokenizers import Regex, Tokenizer, models, pre_tokenizers, trainers

PAD, MASK, CLS, SEP = 0, 1, 2, 3
SPECIAL = ["[PAD]", "[MASK]", "[CLS]", "[SEP]"]
ARCH = dict(d=256, layers=6, heads=8, ff=1024, drop=0.1, max_len=256)  # as in the proposal
SCORE = dict(k=4)  # K interleaved mask passes, ~25% of tokens hidden in each


def train_tokenizer(texts, vocab_size=8000):
    tok = Tokenizer(models.BPE())
    # letter runs / digit runs / single punctuation chars, so every injected symbol is its own token
    tok.pre_tokenizer = pre_tokenizers.Sequence([
        pre_tokenizers.Split(Regex(r"[A-Za-z]+|\d+|[^A-Za-z\d]"), "isolated"),
        pre_tokenizers.ByteLevel(add_prefix_space=False, use_regex=False)])
    tok.train_from_iterator(texts, trainers.BpeTrainer(
        vocab_size=vocab_size, special_tokens=SPECIAL, show_progress=False,
        initial_alphabet=pre_tokenizers.ByteLevel.alphabet()))  # all 256 bytes: nothing is ever [UNK]
    return tok


class LoRALinear(nn.Module):
    def __init__(self, base, r=8, alpha=32, drop=0.1):
        super().__init__()
        self.base, self.scale, self.drop = base, alpha / r, nn.Dropout(drop)
        self.lora_A = nn.Parameter(torch.randn(r, base.in_features) / math.sqrt(base.in_features))
        self.lora_B = nn.Parameter(torch.zeros(base.out_features, r))  # zero init: starts as the base model

    def forward(self, x):
        return self.base(x) + (self.drop(x) @ self.lora_A.T @ self.lora_B.T) * self.scale


def add_lora(model, r=8, alpha=32, drop=0.1):
    """Freeze the base model and put rank-r adapters on every query and value projection."""
    for p in model.parameters():
        p.requires_grad = False
    for b in model.blocks:
        b.q, b.v = LoRALinear(b.q, r, alpha, drop), LoRALinear(b.v, r, alpha, drop)
    return [p for n, p in model.named_parameters() if "lora_" in n]


def lora_state(model):
    return {k: v for k, v in model.state_dict().items() if "lora_" in k}


class Block(nn.Module):
    def __init__(self, d, heads, ff, drop):
        super().__init__()
        self.heads, self.drop = heads, drop
        self.q, self.k, self.v, self.o = (nn.Linear(d, d) for _ in range(4))
        self.n1, self.n2 = nn.LayerNorm(d), nn.LayerNorm(d)
        self.ff = nn.Sequential(nn.Linear(d, ff), nn.GELU(), nn.Dropout(drop), nn.Linear(ff, d))
        self.dp = nn.Dropout(drop)

    def forward(self, x, keep):  # keep: (B,L) True for real tokens
        B, L, D = x.shape
        y = self.n1(x)
        q, k, v = (f(y).view(B, L, self.heads, D // self.heads).transpose(1, 2) for f in (self.q, self.k, self.v))
        a = F.scaled_dot_product_attention(q, k, v, attn_mask=keep[:, None, None, :],
                                           dropout_p=self.drop if self.training else 0.0)
        x = x + self.dp(self.o(a.transpose(1, 2).reshape(B, L, D)))
        return x + self.dp(self.ff(self.n2(x)))


class Autoencoder(nn.Module):
    def __init__(self, vocab, d, layers, heads, ff, drop, max_len):
        super().__init__()
        self.emb = nn.Embedding(vocab, d, padding_idx=PAD)
        pos = torch.arange(max_len)[:, None] * torch.exp(torch.arange(0, d, 2) * (-math.log(10000.0) / d))
        pe = torch.zeros(max_len, d)
        pe[:, 0::2], pe[:, 1::2] = torch.sin(pos), torch.cos(pos)
        self.register_buffer("pos", pe, persistent=False)  # sinusoidal, as in the proposal
        self.blocks = nn.ModuleList(Block(d, heads, ff, drop) for _ in range(layers))
        self.norm, self.head = nn.LayerNorm(d), nn.Linear(d, vocab)
        self.dp = nn.Dropout(drop)

    def forward(self, x):
        keep = x != PAD
        h = self.dp(self.emb(x) + self.pos[: x.size(1)])
        for b in self.blocks:
            h = b(h, keep)
        return self.head(self.norm(h))


def build(vocab, arch=ARCH):
    return Autoencoder(vocab, arch["d"], arch["layers"], arch["heads"], arch["ff"], arch["drop"], arch["max_len"])


def encode(tok, texts, max_len=ARCH["max_len"]):
    if hasattr(tok, "encode_batch"):
        return [e.ids[: max_len - 2] for e in tok.encode_batch(texts)]
    return [tok.encode(t).ids[: max_len - 2] for t in texts]


def collate(seqs):
    L = max(len(s) for s in seqs) + 2
    x = torch.full((len(seqs), L), PAD)
    for i, s in enumerate(seqs):
        x[i, : len(s) + 2] = torch.tensor([CLS, *s, SEP])
    return x


def fit(model, seqs, epochs, bs=32, lr=5e-4, log=None, seed=0, log_every=1):
    """Masked-token training on benign request token ids (only parameters with requires_grad are updated)."""
    g = torch.Generator().manual_seed(seed)
    dev = next(model.parameters()).device
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=lr, weight_decay=0.01)
    steps = epochs * math.ceil(len(seqs) / bs)
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=lr, total_steps=steps, pct_start=0.1)
    scaler = torch.amp.GradScaler('cuda') if dev.type == 'cuda' else None
    chunk_size = bs * 50

    for ep in range(epochs):
        model.train()
        # Megabatch length bucketing: groups similar sequence lengths to reduce padding and speed up attention
        perm = torch.randperm(len(seqs), generator=g).tolist()
        batches = []
        for i in range(0, len(seqs), chunk_size):
            chunk = perm[i:i + chunk_size]
            chunk.sort(key=lambda idx: len(seqs[idx]))
            for j in range(0, len(chunk), bs):
                batches.append(chunk[j:j + bs])
        batch_perm = torch.randperm(len(batches), generator=g).tolist()

        total_loss, n_batches = 0.0, 0
        for bi in batch_perm:
            batch_indices = batches[bi]
            x = collate([seqs[j] for j in batch_indices])
            real = (x != PAD) & (x != CLS) & (x != SEP)
            rate = 0.15 + 0.25 * torch.rand(x.size(0), 1, generator=g)
            m = (torch.rand(x.shape, generator=g) < rate) & real
            m[torch.arange(x.size(0)), real.float().argmax(1)] = True  # >=1 masked token per row
            x, m = x.to(dev), m.to(dev)
            opt.zero_grad()
            if scaler:
                with torch.amp.autocast('cuda', dtype=torch.float16):
                    logits = model(x.masked_fill(m, MASK))
                    loss = F.cross_entropy(logits[m], x[m])
                scaler.scale(loss).backward()
                scaler.step(opt)
                scaler.update()
            else:
                logits = model(x.masked_fill(m, MASK))
                loss = F.cross_entropy(logits[m], x[m])
                loss.backward()
                opt.step()
            sched.step()
            total_loss += loss.item()
            n_batches += 1
        if log and (ep + 1) % log_every == 0:
            log(ep + 1, total_loss / max(1, n_batches))
    return model


@torch.no_grad()
def token_losses(model, id_lists, k=SCORE["k"], max_len=ARCH["max_len"], batch=256):
    """Per-token masked cross-entropy for each id list. Long inputs are scored in max_len windows so padding
    the front of a request cannot push the payload out of view."""
    model.eval()
    dev = next(model.parameters()).device
    rows, owner = [], []  # masked rows, (request index, row positions, target ids, token indices)
    out = [[0.0] * len(ids) for ids in id_lists]  # losses in token order
    C = max_len - 2
    for ri, ids in enumerate(id_lists):
        for s in range(0, max(len(ids), 1), C):
            chunk = ids[s:s + C]
            for j in range(k):
                pos = [p for p in range(len(chunk)) if p % k == j]
                if not pos:
                    continue
                row = [CLS, *chunk, SEP]
                tgt = [chunk[p] for p in pos]
                for p in pos:
                    row[p + 1] = MASK
                rows.append(row)
                owner.append((ri, [p + 1 for p in pos], tgt, [s + p for p in pos]))
    for i in range(0, len(rows), batch):
        part = rows[i:i + batch]
        L = max(len(r) for r in part)
        x = torch.full((len(part), L), PAD)
        for a, r in enumerate(part):
            x[a, :len(r)] = torch.tensor(r)
        if dev.type == 'cuda':
            with torch.amp.autocast('cuda', dtype=torch.float16):
                logp = F.log_softmax(model(x.to(dev)), -1)
        else:
            logp = F.log_softmax(model(x.to(dev)), -1)
        for a in range(len(part)):
            ri, pos, tgt, idx = owner[i + a]
            for j, v in zip(idx, (-logp[a, pos, tgt]).tolist()):
                out[ri][j] = v
    return out


def request_parts(text, enc, losses):
    """(mean token loss, max loss over symbol tokens). A lone injected character (' < ` ; |) is one token among
    ~25, so the mean hides it (a bare `q='` averages 0.5); symbol tokens are therefore scored on their own.
    Novel benign word fragments (a new product name) carry no symbol, so they do not trigger the second term."""
    sym = [l for l, (a, b) in zip(losses, enc.offsets)
           if b > a and not any(c.isalnum() or c.isspace() for c in text[a:b])]
    return (sum(losses) / len(losses) if losses else 0.0, max(sym, default=0.0))


def combine(parts, scale):
    """Anomaly score = the larger of the two components, each divided by its own benign percentile (set in
    train.py), so 1.0 is the alert level. Separate calibration matters: with one shared scale the
    heavier-tailed symbol term dominated and the mean needed to be ~5x normal before it alerted."""
    return max(parts[0] / scale["mean"], parts[1] / scale["sym"])


class Scorer:
    """Loads a trained model directory and scores normalised request strings."""

    def __init__(self, path="model"):
        cfg = json.load(open(os.path.join(path, "config.json")))
        self.cfg, self.threshold = cfg, cfg["threshold"]
        self.tok = Tokenizer.from_file(os.path.join(path, "tokenizer.json"))
        self.model = build(self.tok.get_vocab_size(), cfg["arch"])
        self.model.load_state_dict(torch.load(os.path.join(path, "model.pt"), map_location="cpu"))
        lora = os.path.join(path, "lora.pt")
        if os.path.exists(lora):
            add_lora(self.model)
            self.model.load_state_dict(torch.load(lora, map_location="cpu"), strict=False)
        self.model.eval()

    def _run(self, texts):
        encs = [self.tok.encode(t) for t in texts]
        ls = token_losses(self.model, [e.ids for e in encs], self.cfg["score"]["k"])
        return encs, ls, [combine(request_parts(t, e, l), self.cfg["scale"]) for t, e, l in zip(texts, encs, ls)]

    def explain(self, texts):
        """Return [(score, [(token_text, loss), ...])] so an analyst can see *which* tokens drove the score."""
        encs, ls, scores = self._run(texts)
        return [(s, [(t[a:b], l) for (a, b), l in zip(e.offsets, tl)]) for t, e, tl, s in zip(texts, encs, ls, scores)]

    def score(self, texts):
        return self._run(texts)[2]
