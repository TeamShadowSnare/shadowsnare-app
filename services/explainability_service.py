# import numpy as np
# import shap

# class ExplainabilityService:
#     def __init__(self):
#         self.explainer = None
#         self.feature_names = None

#     def initialize_explainer(self, model, X_train, feature_names):
#         try:
#             self.feature_names = feature_names
#             self.explainer = shap.Explainer(model, X_train, feature_names=feature_names)
#         except Exception as e:
#             print(f"Error initializing SHAP explainer: {e}")
#             self.explainer = None

#     def generate_explanation_for_sample(self, X_scaled, sample, index=None):
#         if self.explainer is None:
#             return "SHAP explainer not initialized."

#         sample = sample.reshape(1, -1)
#         shap_values = self.explainer(sample)

#         values = shap_values[0].values
#         effects = sorted(zip(values, self.feature_names), key=lambda x: abs(x[0]), reverse=True)
#         arrows = ["🟥 ↑" if val > 0 else "🟦 ↓" for val, _ in effects[:3]]
#         explanation = "\n".join(f"{arrow} {name}" for arrow, (_, name) in zip(arrows, effects[:3]))
#         final_score = (shap_values[0].base_values + sum(values)).item()

#         return (
#             f"This file is {'malicious' if final_score > 0.5 else 'benign'}.\n\n"
#             f"Top factors:\n{explanation}\n\nFinal risk score: {final_score:.2f}"
#         )


import shap
import pandas as pd

class ExplainabilityService:
    def __init__(self):
        self.explainer = None
        self.feature_names = None

    def initialize_explainer(self, model, X_train, feature_names):
        self.feature_names = feature_names
        
        # Ensure X_train is a DataFrame for proper column selection
        if not isinstance(X_train, pd.DataFrame):
            X_train = pd.DataFrame(X_train, columns=feature_names)
        
        # Use the actual Keras model, not the wrapper
        # If model is MalwareDetector, get the underlying Keras model
        if hasattr(model, 'model'):
            keras_model = model.model
        else:
            keras_model = model
            
        # Create SHAP explainer with the training data
        self.explainer = shap.Explainer(keras_model, X_train[feature_names])

    def generate_explanation_for_sample(self, X_df, sample_series, index=None):
        if self.explainer is None:
            return "SHAP explainer not initialized."

        # Handle both array and series input
        if hasattr(sample_series, 'values'):
            sample = sample_series.values.reshape(1, -1)
        else:
            sample = sample_series.reshape(1, -1)
            
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