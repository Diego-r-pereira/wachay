import numpy as np
import os
import pathlib
import cv2
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# --- Data Loading and Splitting (same as in train_model.py) ---
# This is necessary to get the exact same test set used for validation.

# Data paths
fire_image_path = "assets/img/fire"
non_fire_path = "assets/img/non_fire"
fire_image_path = pathlib.Path(fire_image_path)
non_fire_path = pathlib.Path(non_fire_path)

# Preprocessing
train_data_images = {
    "Fire": list(fire_image_path.glob("*.jpg")),
    "NonFire": list(non_fire_path.glob("*.jpg"))
}
train_labels = {
    "Fire": 0,
    "NonFire": 1
}

X, y = [], []
for label, images in train_data_images.items():
    for image in images:
        img = cv2.imread(str(image))
        if img is not None:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            img = cv2.resize(img, (180, 180))
            X.append(img)
            y.append(train_labels[label])

X_samp = np.array(X)
y_samp = np.array(y)

X_samp = (X_samp / 255.0) # Normalize pixel values

# Use the same random_state to ensure the split is identical
X_train, X_test, y_train, y_test = train_test_split(X_samp, y_samp, test_size=0.2, random_state=42)


# --- Model Evaluation ---

# Load the newly trained model
model = tf.keras.models.load_model('models/fire_detection_model_v2.h5')

if __name__ == '__main__':
    print("="*60)
    print("Evaluating the fine-tuned VGG16 model (v2) on the test set...")
    print("="*60)

    # 1. Get Loss and Accuracy
    loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
    print(f"Test Accuracy: {accuracy:.4f}")
    print(f"Test Loss: {loss:.4f}")
    print("\n" + "-"*60 + "\n")

    # 2. Get Classification Report (Precision, Recall, F1-Score)
    # Get model predictions
    y_pred_prob = model.predict(X_test, verbose=0)
    y_pred = (y_pred_prob > 0.5).astype("int32")

    # Generate and print the report
    # Note: In our case, 'Fire' is label 0 and 'NonFire' is label 1
    report = classification_report(y_test, y_pred, target_names=['Fire', 'NonFire'])
    print("Classification Report:\n")
    print(report)
    print("="*60)
