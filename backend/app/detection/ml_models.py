"""Model definitions shared by ``ml/training`` and the runtime detector.

``AutoEncoderXGB`` is *inspired by* the AutoEncoder + XGBoost (AEXB) architecture discussed in
the literature survey: an AutoEncoder trained on benign traffic only learns what "normal"
looks like; its latent code and reconstruction error are appended to the raw features and
an XGBoost classifier makes the final decision. It is not a reproduction of the published
model (different data, preprocessing and hyper-parameters).

The AutoEncoder is a scikit-learn MLP (in -> 16 -> latent -> 16 -> in) so no deep-learning
framework is required; the latent code is computed from the fitted weights directly.
"""
from __future__ import annotations

import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(x, 0.0)


def make_xgb(seed: int, **overrides) -> XGBClassifier:
    params = dict(
        n_estimators=400,
        max_depth=5,
        learning_rate=0.06,
        subsample=0.9,
        colsample_bytree=0.9,
        min_child_weight=2,
        reg_lambda=1.0,
        tree_method="hist",
        eval_metric="logloss",
        early_stopping_rounds=30,
        n_jobs=4,
        random_state=seed,
    )
    params.update(overrides)
    return XGBClassifier(**params)


class AutoEncoderXGB:
    def __init__(self, latent_dim: int = 6, hidden: int = 16, seed: int = 42):
        self.latent_dim = latent_dim
        self.hidden = hidden
        self.seed = seed
        self.imputer = SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True)
        self.scaler = StandardScaler()
        self.autoencoder = MLPRegressor(
            hidden_layer_sizes=(hidden, latent_dim, hidden),
            activation="relu",
            alpha=1e-4,
            learning_rate_init=3e-3,
            max_iter=400,
            early_stopping=True,
            n_iter_no_change=15,
            random_state=seed,
        )
        self.classifier = make_xgb(seed)
        self.recon_threshold_: float | None = None

    # -- AutoEncoder helpers -------------------------------------------------------------
    def _scaled(self, X: np.ndarray) -> np.ndarray:
        return self.scaler.transform(self.imputer.transform(X))

    def latent(self, Xs: np.ndarray) -> np.ndarray:
        w, b = self.autoencoder.coefs_, self.autoencoder.intercepts_
        h = _relu(Xs @ w[0] + b[0])
        return _relu(h @ w[1] + b[1])

    def reconstruction_error(self, Xs: np.ndarray) -> np.ndarray:
        return np.mean((self.autoencoder.predict(Xs) - Xs) ** 2, axis=1)

    def augment(self, X: np.ndarray) -> np.ndarray:
        Xs = self._scaled(X)
        err = self.reconstruction_error(Xs)[:, None]
        return np.hstack([X, self.latent(Xs), np.log1p(err)])

    # -- sklearn-like API ----------------------------------------------------------------
    def fit(self, X: np.ndarray, y: np.ndarray, X_val: np.ndarray, y_val: np.ndarray) -> "AutoEncoderXGB":
        benign = X[y == 0]
        self.imputer.fit(benign)
        self.scaler.fit(self.imputer.transform(benign))
        Xb = self._scaled(benign)
        self.autoencoder.fit(Xb, Xb)
        self.recon_threshold_ = float(np.quantile(self.reconstruction_error(Xb), 0.99))
        self.classifier.fit(self.augment(X), y, eval_set=[(self.augment(X_val), y_val)], verbose=False)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.classifier.predict_proba(self.augment(X))

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)

    @property
    def augmented_feature_names(self) -> list[str]:
        from app.telemetry.features import FEATURES

        return FEATURES + [f"latent_{i}" for i in range(self.latent_dim)] + ["ae_recon_error"]
