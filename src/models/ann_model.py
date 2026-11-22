"""Artificial Neural Network (3 Hidden Layers, Dropout, Early Stopping) for ML-IDS.

Supports TensorFlow/Keras backend when installed and includes a self-contained
3-hidden-layer Dropout + EarlyStopping neural network engine compatible with
scikit-learn and .pkl serialization.
"""

from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin

from src.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import tensorflow as tf
    from tensorflow.keras import Sequential
    from tensorflow.keras.callbacks import EarlyStopping
    from tensorflow.keras.layers import Dense, Dropout, Input

    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False


class ThreeLayerDropoutANN(BaseEstimator, ClassifierMixin):
    """3-Hidden-Layer Artificial Neural Network with Dropout and Early Stopping.

    Architecture:
        Input -> Dense(128, ReLU) -> Dropout(0.3)
              -> Dense(64, ReLU)  -> Dropout(0.2)
              -> Dense(32, ReLU)  -> Dropout(0.2)
              -> Dense(num_classes, Softmax)
    """

    def __init__(
        self,
        hidden_units: Tuple[int, int, int] = (128, 64, 32),
        dropout_rates: Tuple[float, float, float] = (0.3, 0.2, 0.2),
        learning_rate: float = 0.002,
        batch_size: int = 128,
        epochs: int = 45,
        patience: int = 6,
        random_state: int = 42,
    ) -> None:
        """Initialize the 3-hidden-layer neural network hyperparameters.

        Args:
            hidden_units: Tuple of units for the 3 hidden layers.
            dropout_rates: Tuple of dropout probabilities for the 3 hidden layers.
            learning_rate: Adam optimizer learning rate.
            batch_size: Mini-batch size for training.
            epochs: Maximum training epochs.
            patience: Early stopping patience on validation loss.
            random_state: Seed for deterministic weight initialization and dropout.
        """
        self.hidden_units = hidden_units
        self.dropout_rates = dropout_rates
        self.learning_rate = learning_rate
        self.batch_size = batch_size
        self.epochs = epochs
        self.patience = patience
        self.random_state = random_state
        self.weights_: List[np.ndarray] = []
        self.biases_: List[np.ndarray] = []
        self.classes_: np.ndarray = np.array([])
        self.history_: Dict[str, List[float]] = {
            "train_loss": [],
            "val_loss": [],
            "val_accuracy": [],
        }
        self.backend_used_: str = "tensorflow.keras" if HAS_TENSORFLOW else "keras_compatible_numpy_ann"

    @staticmethod
    def _relu(z: np.ndarray) -> np.ndarray:
        return np.maximum(0.0, z)

    @staticmethod
    def _softmax(z: np.ndarray) -> np.ndarray:
        shifted = z - np.max(z, axis=1, keepdims=True)
        exp_z = np.exp(shifted)
        return exp_z / (np.sum(exp_z, axis=1, keepdims=True) + 1e-12)

    def _init_params(self, input_dim: int, num_classes: int, rng: np.random.Generator) -> None:
        layer_dims = [input_dim, *self.hidden_units, num_classes]
        self.weights_ = []
        self.biases_ = []
        for i in range(len(layer_dims) - 1):
            # He initialization
            scale = np.sqrt(2.0 / layer_dims[i])
            w = rng.normal(0.0, scale, size=(layer_dims[i], layer_dims[i + 1]))
            b = np.zeros((1, layer_dims[i + 1]), dtype=float)
            self.weights_.append(w)
            self.biases_.append(b)

    def _forward(
        self, X: np.ndarray, training: bool = False, rng: Optional[np.random.Generator] = None
    ) -> Tuple[np.ndarray, List[Tuple[np.ndarray, np.ndarray, Optional[np.ndarray]]]]:
        a = X
        caches = []
        # 3 Hidden Layers with ReLU and Inverted Dropout
        for idx in range(3):
            z = a @ self.weights_[idx] + self.biases_[idx]
            h = self._relu(z)
            mask = None
            rate = self.dropout_rates[idx]
            if training and rate > 0.0 and rng is not None:
                keep_prob = 1.0 - rate
                mask = (rng.random(h.shape) < keep_prob).astype(float) / keep_prob
                h = h * mask
            caches.append((a, z, mask))
            a = h

        # Output Softmax Layer
        logits = a @ self.weights_[3] + self.biases_[3]
        probs = self._softmax(logits)
        caches.append((a, logits, None))
        return probs, caches

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
    ) -> "ThreeLayerDropoutANN":
        """Train the 3-hidden-layer neural network with Dropout and EarlyStopping.

        Args:
            X: Training feature matrix.
            y: Training integer labels.
            X_val: Optional validation feature matrix for early stopping.
            y_val: Optional validation integer labels.

        Returns:
            Fitted ThreeLayerDropoutANN instance.
        """
        rng = np.random.default_rng(self.random_state)
        self.classes_ = np.unique(y)
        num_classes = len(self.classes_)
        n_samples, input_dim = X.shape

        if X_val is None or y_val is None:
            split_idx = int(0.85 * n_samples)
            perm = rng.permutation(n_samples)
            X_tr, y_tr = X[perm[:split_idx]], y[perm[:split_idx]]
            X_v, y_v = X[perm[split_idx:]], y[perm[split_idx:]]
        else:
            X_tr, y_tr = X, y
            X_v, y_v = X_val, y_val

        if HAS_TENSORFLOW:
            tf.random.set_seed(self.random_state)
            model = Sequential(
                [
                    Input(shape=(input_dim,)),
                    Dense(self.hidden_units[0], activation="relu"),
                    Dropout(self.dropout_rates[0]),
                    Dense(self.hidden_units[1], activation="relu"),
                    Dropout(self.dropout_rates[1]),
                    Dense(self.hidden_units[2], activation="relu"),
                    Dropout(self.dropout_rates[2]),
                    Dense(num_classes, activation="softmax"),
                ]
            )
            model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=self.learning_rate),
                loss="sparse_categorical_crossentropy",
                metrics=["accuracy"],
            )
            early_stop = EarlyStopping(
                monitor="val_loss", patience=self.patience, restore_best_weights=True
            )
            hist = model.fit(
                X_tr,
                y_tr,
                validation_data=(X_v, y_v),
                epochs=self.epochs,
                batch_size=self.batch_size,
                callbacks=[early_stop],
                verbose=0,
            )
            # Extract weights into numpy arrays so model is 100% portable with joblib/pickle
            dense_layers = [lyr for lyr in model.layers if isinstance(lyr, Dense)]
            self.weights_ = [lyr.get_weights()[0] for lyr in dense_layers]
            self.biases_ = [lyr.get_weights()[1].reshape(1, -1) for lyr in dense_layers]
            self.history_["train_loss"] = [float(v) for v in hist.history.get("loss", [])]
            self.history_["val_loss"] = [float(v) for v in hist.history.get("val_loss", [])]
            self.history_["val_accuracy"] = [float(v) for v in hist.history.get("val_accuracy", [])]
            return self

        # Self-contained Adam + Inverted Dropout + EarlyStopping training loop
        self._init_params(input_dim, num_classes, rng)

        # Adam first & second moment buffers
        m_w = [np.zeros_like(w) for w in self.weights_]
        v_w = [np.zeros_like(w) for w in self.weights_]
        m_b = [np.zeros_like(b) for b in self.biases_]
        v_b = [np.zeros_like(b) for b in self.biases_]
        beta1, beta2, eps = 0.9, 0.999, 1e-8
        step = 0

        best_val_loss = float("inf")
        best_weights = [w.copy() for w in self.weights_]
        best_biases = [b.copy() for b in self.biases_]
        wait = 0

        y_tr_onehot = np.eye(num_classes)[y_tr]
        y_v_onehot = np.eye(num_classes)[y_v]

        for epoch in range(1, self.epochs + 1):
            perm = rng.permutation(len(X_tr))
            X_shuf = X_tr[perm]
            y_shuf = y_tr_onehot[perm]
            epoch_losses = []

            for start in range(0, len(X_tr), self.batch_size):
                step += 1
                xb = X_shuf[start : start + self.batch_size]
                yb = y_shuf[start : start + self.batch_size]
                bs = len(xb)

                probs, caches = self._forward(xb, training=True, rng=rng)
                loss = -np.mean(np.sum(yb * np.log(probs + 1e-12), axis=1))
                epoch_losses.append(float(loss))

                # Backpropagation through Softmax + 3 Dropout ReLU layers
                dz = (probs - yb) / bs
                grads_w = [None] * 4
                grads_b = [None] * 4

                a3, _, _ = caches[3]
                grads_w[3] = a3.T @ dz + 1e-4 * self.weights_[3]
                grads_b[3] = np.sum(dz, axis=0, keepdims=True)
                da = dz @ self.weights_[3].T

                for idx in [2, 1, 0]:
                    a_prev, z_curr, mask = caches[idx]
                    if mask is not None:
                        da = da * mask
                    dz_curr = da * (z_curr > 0.0)
                    grads_w[idx] = a_prev.T @ dz_curr + 1e-4 * self.weights_[idx]
                    grads_b[idx] = np.sum(dz_curr, axis=0, keepdims=True)
                    if idx > 0:
                        da = dz_curr @ self.weights_[idx].T

                # Adam parameter update
                lr_t = self.learning_rate * np.sqrt(1.0 - beta2**step) / (1.0 - beta1**step)
                for idx in range(4):
                    m_w[idx] = beta1 * m_w[idx] + (1.0 - beta1) * grads_w[idx]
                    v_w[idx] = beta2 * v_w[idx] + (1.0 - beta2) * (grads_w[idx] ** 2)
                    self.weights_[idx] -= lr_t * m_w[idx] / (np.sqrt(v_w[idx]) + eps)

                    m_b[idx] = beta1 * m_b[idx] + (1.0 - beta1) * grads_b[idx]
                    v_b[idx] = beta2 * v_b[idx] + (1.0 - beta2) * (grads_b[idx] ** 2)
                    self.biases_[idx] -= lr_t * m_b[idx] / (np.sqrt(v_b[idx]) + eps)

            # Validation evaluation for EarlyStopping
            val_probs, _ = self._forward(X_v, training=False)
            val_loss = float(-np.mean(np.sum(y_v_onehot * np.log(val_probs + 1e-12), axis=1)))
            val_preds = np.argmax(val_probs, axis=1)
            val_acc = float(np.mean(val_preds == y_v))

            self.history_["train_loss"].append(float(np.mean(epoch_losses)))
            self.history_["val_loss"].append(val_loss)
            self.history_["val_accuracy"].append(val_acc)

            if val_loss < best_val_loss - 1e-4:
                best_val_loss = val_loss
                best_weights = [w.copy() for w in self.weights_]
                best_biases = [b.copy() for b in self.biases_]
                wait = 0
            else:
                wait += 1
                if wait >= self.patience:
                    logger.info(
                        "ANN EarlyStopping triggered at epoch %d (best val_loss=%.4f, val_acc=%.4f)",
                        epoch,
                        best_val_loss,
                        val_acc,
                    )
                    break

        self.weights_ = best_weights
        self.biases_ = best_biases
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Compute class probability distribution for input samples.

        Args:
            X: Feature matrix.

        Returns:
            Array of shape (n_samples, num_classes) with probabilities summing to 1.
        """
        probs, _ = self._forward(np.asarray(X, dtype=float), training=False)
        return probs

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict integer class indices for input samples.

        Args:
            X: Feature matrix.

        Returns:
            Predicted integer class labels.
        """
        probs = self.predict_proba(X)
        return self.classes_[np.argmax(probs, axis=1)]
