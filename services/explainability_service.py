import shap
import numpy as np

class ExplainabilityService:
    def __init__(self, model, X_train, feature_names):
        self.feature_names = feature_names
        self.explainer = shap.Explainer(model.predict, X_train)

    def generate_explanations(self, feature_data, predictions=None):
        explanations = []
        for i, sample in enumerate(feature_data):
            sample = sample.reshape(1, -1).astype(float)
            shap_values = self.explainer(sample)
            effects = sorted(zip(shap_values[0].values, self.feature_names), key=lambda x: abs(x[0]), reverse=True)
            arrows = ["🟥 ↑" if val > 0 else "🟦 ↓" for val, _ in effects[:3]]
            explanation = "\n".join(f"{arrow} {name}" for arrow, (_, name) in zip(arrows, effects[:3]))
            score = (shap_values[0].base_values + shap_values[0].values.sum()).item()
            label = "malicious" if score > 0.5 else "benign"
            explanations.append(f"Process {i+1}: {label}\n{explanation}\n---")
        return "\n\n".join(explanations)
