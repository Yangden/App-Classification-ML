import os
import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# List of paths to input files
file_paths = [
    "./bidirectional_tls_flows_features.csv",
    "./labeled_tls_flows_features.csv",
]

# Model directory and path
model_dir = "./model"
os.makedirs(model_dir, exist_ok=True)
model_path = os.path.join(model_dir, "random_forest_model.pkl")

# Features to use
feature_columns = [
    "Percentile_10",
    "Percentile_20",
    "Percentile_30",
    "Percentile_40",
    "Percentile_50",
    "Percentile_60",
    "Percentile_70",
    "Percentile_80",
    "Percentile_90",
    "Min_Length",
    "Max_Length",
    "Mean_Length",
    "StdDev_Length",
    "Variance_Length",
    "Encrypted_Flow_Payload",
]

# Load data from all files
dataframes = [pd.read_csv(file_path) for file_path in file_paths]
data = pd.concat(dataframes, ignore_index=True)


# Preprocess data
# For "Encrypted_Flow_Payload", use the first 256 bytes (padded if necessary)
def process_payload(payload):
    payload_bytes = bytes.fromhex(payload) if isinstance(payload, str) else b""
    padded_payload = payload_bytes[:256].ljust(
        256, b"\x00"
    )  # Truncate or pad to 256 bytes
    return list(padded_payload)


data["Processed_Encrypted_Flow_Payload"] = data["Encrypted_Flow_Payload"].apply(
    process_payload
)

# Expand the processed payload into separate columns
payload_columns = [f"Payload_Byte_{i}" for i in range(256)]
payload_df = pd.DataFrame(
    data["Processed_Encrypted_Flow_Payload"].tolist(), columns=payload_columns
)

# Combine payload columns with the rest of the features
data = pd.concat([data, payload_df], axis=1)

# Final feature set
X = data[feature_columns[:-1] + payload_columns]
y = data["Label"].astype(str)  # Assuming "Label" is the target column

# Train or load model
if os.path.exists(model_path):
    print("Loading existing model...")
    with open(model_path, "rb") as model_file:
        model = pickle.load(model_file)
else:
    print("Training new model...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Save the model
    with open(model_path, "wb") as model_file:
        pickle.dump(model, model_file)

    # Evaluate the model
    y_pred = model.predict(X_test)
    print("Model performance:")
    print(classification_report(y_test, y_pred))

# Predict using the model
predictions = model.predict(X)
data["Predictions"] = predictions

# Print classification report for the entire dataset
y_true = y
print("Classification report for the entire dataset:")
print(classification_report(y_true, predictions))

# Save predictions to a new CSV
output_file = "predictions_output.csv"
data.to_csv(output_file, index=False)
print(f"Predictions saved to {output_file}")
