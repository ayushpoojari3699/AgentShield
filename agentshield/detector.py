"""Prompt-injection detector = normalisation + rules + a small ML classifier.

    score = max(rule_score, ml_probability)      flagged if score >= threshold

* Normalisation undoes cheap obfuscation: zero-width characters, l33t-speak digits,
  s p a c e d  letters and repeated whitespace.
* Rules catch well-known phrasings with near-zero false alarms.
* The classifier (TF-IDF word + character n-grams -> logistic regression) generalises to
  phrasings the rules don't list.
* The threshold is chosen on a validation split by COST: a missed attack is assumed to
  cost 10x a false alarm (a blocked genuine invoice only means a human looks at it).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "detector.joblib"
MISS_COST, FALSE_ALARM_COST = 10.0, 1.0

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

RULES: list[tuple[str, float]] = [
    (r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all|your)\b.{0,20}"
     r"\b(instructions?|rules?|guidelines?|prompts?|everything)\b", 0.95),
    (r"\byou are now\b|\bact as\b.{0,40}\b(no|without) (restrictions?|limits?|checks?)\b", 0.9),
    (r"\bpretend (you are|to be)\b", 0.8),
    (r"\b(call|invoke|use|run|trigger)\b.{0,30}\b(approve_payment|check_policy|payment function|tool)\b", 0.9),
    (r"\bapprove_payment\b", 0.7),
    (r"\b(always|just)\b.{0,20}\breturn approved\b", 0.9),
    (r"\b(send|email|reply with|include)\b.{0,60}\b(vendor (master|database|list)|every vendor|all (stored )?vendor)\b", 0.9),
    (r"\b(new|updated) instructions\b", 0.75),
    (r"\b(rules|instructions)\b.{0,15}\b(bhool|ignore|chhod)\b|\b(bhool|chhod) (jao|do)\b", 0.9),
    (r"\bdo not follow your (rules|guidelines|instructions)\b", 0.95),
]
_RULES = [(re.compile(p, re.I | re.S), w) for p, w in RULES]


def normalise(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    # join s p a c e d  o u t  letters: "i g n o r e" -> "ignore"
    t = re.sub(r"\b(?:\w ){3,}\w\b", lambda m: m.group(0).replace(" ", ""), t)
    # l33t only inside words that mix letters and digits (keeps amounts and account numbers)
    t = re.sub(r"\b(?=\w*[a-zA-Z])(?=\w*[0-9])\w+\b", lambda m: m.group(0).translate(LEET), t)
    return re.sub(r"\s+", " ", t).strip().lower()


def rule_score(text: str) -> tuple[float, list[str]]:
    t = normalise(text)
    hits = [(w, p.pattern[:60]) for p, w in _RULES if p.search(t)]
    return (max(w for w, _ in hits), [h for _, h in hits]) if hits else (0.0, [])


def build_classifier() -> Pipeline:
    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
    ])
    return Pipeline([("features", features),
                     ("clf", LogisticRegression(C=2.0, class_weight="balanced", max_iter=2000))])


@dataclass
class Detector:
    model: Pipeline | None = None
    threshold: float = 0.5
    info: dict = field(default_factory=dict)

    def ml_proba(self, texts: list[str]) -> np.ndarray:
        if self.model is None:
            return np.zeros(len(texts))
        return self.model.predict_proba([normalise(t) for t in texts])[:, 1]

    def scores(self, texts: list[str], use_rules: bool = True, use_ml: bool = True) -> np.ndarray:
        ml = self.ml_proba(texts) if use_ml else np.zeros(len(texts))
        rules = np.array([rule_score(t)[0] for t in texts]) if use_rules else np.zeros(len(texts))
        return np.maximum(ml, rules)

    def check(self, text: str) -> dict:
        r, hits = rule_score(text)
        ml = float(self.ml_proba([text])[0])
        score = max(r, ml)
        return {"score": round(score, 3), "flagged": score >= self.threshold,
                "rule_score": r, "ml_score": round(ml, 3), "rule_hits": hits}

    # ------------------------------------------------------------------ training
    @classmethod
    def train(cls, texts: list[str], labels: list[int], seed: int = 0) -> "Detector":
        x_tr, x_val, y_tr, y_val = train_test_split(texts, labels, test_size=0.25,
                                                    stratify=labels, random_state=seed)
        model = build_classifier().fit([normalise(t) for t in x_tr], y_tr)
        det = cls(model=model)
        s_val, y_val = det.scores(x_val), np.array(y_val)
        best = None
        for th in np.round(np.arange(0.05, 0.96, 0.01), 2):
            pred = s_val >= th
            cost = MISS_COST * np.sum(~pred & (y_val == 1)) + FALSE_ALARM_COST * np.sum(pred & (y_val == 0))
            if best is None or cost < best[0] or (cost == best[0] and abs(th - 0.5) < abs(best[1] - 0.5)):
                best = (cost, float(th))
        det.threshold = best[1]
        # refit on all training data with the chosen threshold
        det.model = build_classifier().fit([normalise(t) for t in texts], labels)
        det.info = {"n_train": len(texts), "validation_cost": float(best[0]),
                    "cost_ratio": f"{MISS_COST:.0f}:{FALSE_ALARM_COST:.0f}"}
        return det

    def save(self, path: Path = MODEL_PATH) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "threshold": self.threshold, "info": self.info}, path)
        return path

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> "Detector":
        d = joblib.load(path)
        return cls(model=d["model"], threshold=d["threshold"], info=d.get("info", {}))


def load_or_train(path: Path = MODEL_PATH) -> Detector:
    """Load the saved detector, or train one from the synthetic TRAIN split (a few seconds)."""
    if path.exists():
        return Detector.load(path)
    from .data import detector_dataset
    texts, labels, _ = detector_dataset("train")
    det = Detector.train(texts, labels)
    det.save(path)
    return det


if __name__ == "__main__":  # python -m agentshield.detector  -> retrain and save
    from .data import detector_dataset
    texts, labels, _ = detector_dataset("train")
    det = Detector.train(texts, labels)
    print(f"Trained on {len(texts)} texts; threshold {det.threshold}; saved to {det.save()}")
