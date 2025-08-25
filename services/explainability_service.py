"""
Explainability service (SHAP).

Wraps SHAP explainer creation and per-sample textual attributions for the UI.
- `initialize_explainer(...)` builds a SHAP Explainer for a (Keras) model.
- `generate_explanation_for_sample(...)` returns a short, readable summary of
  the top contributing features and a final risk score.
"""


import shap
import pandas as pd

class ExplainabilityService:
    """Provides SHAP-based explanations for model predictions."""
    def __init__(self):
        # Lazily-initialized SHAP explainer and the feature schema it expects
        self.explainer = None
        self.feature_names = None

    def initialize_explainer(self, model, X_train, feature_names):
        """
        Create a SHAP Explainer bound to the given model and feature schema.

        Parameters
        ----------
        model : keras.Model or wrapper
            The trained classifier; if it has `.model`, the inner Keras model is used.
        X_train : pandas.DataFrame or array-like
            Background data for SHAP (used to estimate feature contributions).
        feature_names : list[str]
            Ordered feature names used by the model (must match training).
        """
        self.feature_names = feature_names
        
        # Ensure background data is a DataFrame with the expected columns
        if not isinstance(X_train, pd.DataFrame):
            X_train = pd.DataFrame(X_train, columns=feature_names)
        
        # Unwrap if a wrapper object exposes the actual Keras model via `.model`
        if hasattr(model, 'model'):
            keras_model = model.model
        else:
            keras_model = model
        
        # Build the SHAP explainer using background data restricted to our features
        self.explainer = shap.Explainer(keras_model, X_train[feature_names])

    def generate_explanation_for_sample(self, X_df, sample_series, index=None):
        """
        Produce a succinct text explanation for a single sample.

        Parameters
        ----------
        X_df : pandas.DataFrame
            (Unused here, but kept for potential future context needs.)
        sample_series : pandas.Series or array-like
            The sample's feature values (must align with `feature_names` order).
        index : int | None
            Optional index for display purposes (not required by logic).

        Returns
        -------
        str
            Human-readable explanation containing:
            - predicted class (based on final risk score threshold 0.5),
            - top 3 contributing features with direction arrows,
            - final risk score (base_value + sum of SHAP values).
        """
        if self.explainer is None:
            return "SHAP explainer not initialized."

        # Convert input to 2D array shape (1, n_features) for the explainer
        if hasattr(sample_series, 'values'):
            sample = sample_series.values.reshape(1, -1)
        else:
            sample = sample_series.reshape(1, -1)
        
        # Compute SHAP values for this single sample
        shap_values = self.explainer(sample)
        values = shap_values[0].values # per-feature contribution

         # Rank features by absolute impact (top 3 shown)
        effects = sorted(zip(values, self.feature_names), key=lambda x: abs(x[0]), reverse=True)
        arrows = ["🟥 ↑" if val > 0 else "🟦 ↓" for val, _ in effects[:3]]
        explanation = "\n".join(f"{arrow} {name}" for arrow, (_, name) in zip(arrows, effects[:3]))

        # Combine base value with contributions to get a final risk score
        final_score = (shap_values[0].base_values + sum(values)).item()
        return (
            f"This file is {'malicious' if final_score > 0.5 else 'benign'}.\n\n"
            f"Top factors:\n{explanation}\n\nFinal risk score: {final_score:.2f}"
        )