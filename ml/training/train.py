"""Train and evaluate the SessionGuard detection models.

Models: rule-based detector (no training), Logistic Regression, XGBoost, AutoEncoder+XGBoost.
Splitting is by *session group* (GroupShuffleSplit) so no session appears in more than one
split - this is the main defence against the leakage that inflates request-level metrics.

A second, harder evaluation (leave-one-attack-out) trains with the ``bitm_relay`` attack family
removed and tests on it, to show generalisation to an unseen attack type.

Artifacts written to ml/artifacts/: logreg.joblib, xgboost.joblib, aexgb.joblib,
manifest.json, metrics.json, feature_importance.json.
Run: ``python ml/training/train.py --dataset ml/datasets/dataset.parquet --seed 42``
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.detection.ml_models import AutoEncoderXGB, make_xgb  # noqa: E402
from app.detection.rules import extract_evidence  # noqa: E402
from app.risk.policy import DEFAULT_POLICY  # noqa: E402
from app.telemetry.features import FEATURES  # noqa: E402

ARTIFACTS = ROOT / "ml" / "artifacts"


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        alt = path.with_suffix(".csv")
        if alt.exists():
            return pd.read_csv(alt)
        raise FileNotFoundError(f"dataset not found: {path}")
    return pd.read_parquet(path) if path.suffix == ".parquet" else pd.read_csv(path)


def group_split(df: pd.DataFrame, seed: int) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    groups = df["session_id"].values
    idx = np.arange(len(df))
    tr, tmp = next(GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=seed).split(idx, groups=groups))
    tmp_groups = groups[tmp]
    va_rel, te_rel = next(GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=seed).split(tmp, groups=tmp_groups))
    return df.iloc[tr].copy(), df.iloc[tmp[va_rel]].copy(), df.iloc[tmp[te_rel]].copy()


def rule_scores(df: pd.DataFrame) -> np.ndarray:
    weights = DEFAULT_POLICY.weights.model_dump()
    out = np.zeros(len(df))
    recs = df[FEATURES].to_dict("records")
    for i, feats in enumerate(recs):
        remaining = 1.0
        for ev in extract_evidence(feats):
            w = weights.get(ev.key, 0.0)
            remaining *= 1.0 - max(0.0, min(1.0, w * ev.strength / 100.0))
        out[i] = 1.0 - remaining
    return out


def _metrics(y: np.ndarray, prob: np.ndarray, threshold: float = 0.5) -> dict:
    pred = (prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": round(float(accuracy_score(y, pred)), 4),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y, prob)), 4) if len(np.unique(y)) > 1 else None,
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "support": {"positive": int(y.sum()), "negative": int((y == 0).sum())},
        "threshold": threshold,
    }


def _inference_latency(predict, X: np.ndarray, n: int = 300) -> dict:
    sample = X[:n] if len(X) >= n else X
    times = []
    for row in sample:
        t0 = time.perf_counter()
        predict(row.reshape(1, -1))
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    return {"median": round(float(np.median(times)), 4), "p95": round(float(times[int(0.95 * (len(times) - 1))]), 4),
            "mean": round(float(np.mean(times)), 4)}


def train_models(train: pd.DataFrame, val: pd.DataFrame, seed: int) -> dict:
    Xtr, ytr = train[FEATURES].to_numpy(float), train["label"].to_numpy(int)
    Xva, yva = val[FEATURES].to_numpy(float), val["label"].to_numpy(int)
    pos = max(1, ytr.sum())
    spw = float((len(ytr) - pos) / pos)

    logreg = Pipeline([
        ("impute", SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True)),
        ("scale", StandardScaler()),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=0.6, random_state=seed)),
    ]).fit(Xtr, ytr)

    xgb = make_xgb(seed, scale_pos_weight=spw)
    xgb.fit(Xtr, ytr, eval_set=[(Xva, yva)], verbose=False)

    aexgb = AutoEncoderXGB(seed=seed)
    aexgb.classifier = make_xgb(seed, scale_pos_weight=spw)
    aexgb.fit(Xtr, ytr, Xva, yva)

    return {"logreg": logreg, "xgboost": xgb, "aexgb": aexgb}


def evaluate_all(models: dict, splits: dict[str, pd.DataFrame]) -> dict:
    results: dict[str, dict] = {}
    predictors = {
        "rules": lambda X: rule_scores(pd.DataFrame(X, columns=FEATURES)),
        "logreg": lambda X: models["logreg"].predict_proba(X)[:, 1],
        "xgboost": lambda X: models["xgboost"].predict_proba(X)[:, 1],
        "aexgb": lambda X: models["aexgb"].predict_proba(X)[:, 1],
    }
    for name, predict in predictors.items():
        results[name] = {}
        for split_name, df in splits.items():
            X, y = df[FEATURES].to_numpy(float), df["label"].to_numpy(int)
            prob = predict(X)
            m = _metrics(y, prob)
            if split_name == "test":
                m["inference_ms"] = _inference_latency(predict, X)
                # Per-scenario recall on the test split (how each attack family is detected).
                by_scn = {}
                for scn in sorted(df[df.label == 1]["scenario"].unique()):
                    mask = (df["scenario"] == scn).to_numpy()
                    by_scn[scn] = round(float(recall_score(y[mask], (prob[mask] >= 0.5).astype(int), zero_division=0)), 4)
                m["recall_by_scenario"] = by_scn
            results[name][split_name] = m
    return results


def leave_one_attack_out(df: pd.DataFrame, held: str, seed: int) -> dict:
    train_df = df[df["scenario"] != held]
    tr, va, _ = group_split(train_df, seed)
    test_df = df[df["scenario"] == held]
    # Pair the held-out attack with unseen-but-normal sessions for a balanced-ish test.
    normals = df[df["scenario"] == "normal"].sample(min(len(test_df), (df["scenario"] == "normal").sum()),
                                                     random_state=seed)
    test = pd.concat([test_df, normals])
    models = train_models(tr, va, seed)
    X, y = test[FEATURES].to_numpy(float), test["label"].to_numpy(int)
    return {name: _metrics(y, (predict(X))) for name, predict in {
        "xgboost": lambda X: models["xgboost"].predict_proba(X)[:, 1],
        "aexgb": lambda X: models["aexgb"].predict_proba(X)[:, 1],
    }.items()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", type=Path, default=ROOT / "ml" / "datasets" / "dataset.parquet")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--skip-loao", action="store_true", help="skip the leave-one-attack-out generalisation test")
    args = ap.parse_args()

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    df = load_dataset(args.dataset)
    meta_path = args.dataset.parent / "dataset_meta.json"
    dataset_meta = json.loads(meta_path.read_text()) if meta_path.exists() else {"dataset_version": "unknown"}

    train, val, test = group_split(df, args.seed)
    print(f"split (sessions): train={train.session_id.nunique()} val={val.session_id.nunique()} test={test.session_id.nunique()}")
    assert set(train.session_id).isdisjoint(test.session_id), "LEAKAGE: session in train and test"

    t0 = time.perf_counter()
    models = train_models(train, val, args.seed)
    train_s = time.perf_counter() - t0
    results = evaluate_all(models, {"train": train, "validation": val, "test": test})

    loao = {}
    if not args.skip_loao:
        print("leave-one-attack-out: holding out bitm_relay ...")
        loao = {"bitm_relay": leave_one_attack_out(df, "bitm_relay", args.seed)}

    for name in ("logreg", "xgboost", "aexgb"):
        joblib.dump(models[name], ARTIFACTS / f"{name}.joblib")

    # Feature importances (XGBoost gain + logreg coefficients).
    importance = {
        "xgboost": dict(sorted(zip(FEATURES, (float(v) for v in models["xgboost"].feature_importances_)),
                               key=lambda kv: kv[1], reverse=True)),
        "logreg": dict(sorted(zip(FEATURES, (float(v) for v in models["logreg"].named_steps["clf"].coef_[0])),
                              key=lambda kv: abs(kv[1]), reverse=True)),
    }
    (ARTIFACTS / "feature_importance.json").write_text(json.dumps(importance, indent=2))

    manifest = {
        "dataset_version": dataset_meta.get("dataset_version"), "seed": args.seed,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "train_seconds": round(train_s, 2),
        "features": FEATURES, "models": ["rules", "logreg", "xgboost", "aexgb"],
        "class_distribution": dataset_meta.get("class_distribution"), "scenarios": list(dataset_meta.get("scenarios", {})),
        "splits": {"train_sessions": int(train.session_id.nunique()), "val_sessions": int(val.session_id.nunique()),
                   "test_sessions": int(test.session_id.nunique()), "method": "GroupShuffleSplit by session_id (70/15/15)"},
    }
    (ARTIFACTS / "manifest.json").write_text(json.dumps(manifest, indent=2))
    metrics = {"manifest": manifest, "results": results, "leave_one_attack_out": loao,
               "generated_at": manifest["trained_at"]}
    (ARTIFACTS / "metrics.json").write_text(json.dumps(metrics, indent=2))

    print(f"\ntrained in {train_s:.1f}s. Test-split headline metrics:")
    print(f"{'model':<10}{'acc':>8}{'prec':>8}{'rec':>8}{'f1':>8}{'auc':>8}{'fpr':>8}{'infer_ms':>10}")
    for name in ("rules", "logreg", "xgboost", "aexgb"):
        m = results[name]["test"]
        inf = m.get("inference_ms", {}).get("median", 0)
        auc = m["roc_auc"] if m["roc_auc"] is not None else 0
        print(f"{name:<10}{m['accuracy']:>8.3f}{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>8.3f}"
              f"{auc:>8.3f}{m['false_positive_rate']:>8.3f}{inf:>10.3f}")
    print(f"\nartifacts written to {ARTIFACTS}")


if __name__ == "__main__":
    main()
