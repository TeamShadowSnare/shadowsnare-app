import numpy as np
import shap

class ExplainabilityService:
    def __init__(self, model, X_train, feature_names):
        self.feature_names = feature_names
        self.explainer = shap.Explainer(model, X_train, feature_names=feature_names)

    def generate_explanation_for_sample(self, X_scaled, sample, index=None):
        sample = sample.reshape(1, -1)
        shap_values = self.explainer(sample)

        values = shap_values[0].values
        effects = sorted(zip(values, self.feature_names), key=lambda x: abs(x[0]), reverse=True)
        arrows = ["🟥 ↑" if val > 0 else "🟦 ↓" for val, _ in effects[:3]]
        explanation = "\n".join(f"{arrow} {name}" for arrow, (_, name) in zip(arrows, effects[:3]))
        final_score = (shap_values[0].base_values + sum(values)).item()

        return (
            f"This file is {'malicious' if final_score > 0.5 else 'benign'}.\n\n"
            f"Top factors:\n{explanation}\n\nFinal risk score: {final_score:.2f}"
        )
