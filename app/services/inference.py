import os
import cv2
import numpy as np
import tf_keras as keras

# Define base path dynamically to avoid relative Cwd errors
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(BASE_DIR, "models", "fire_detection_model_mobilenetv2.h5")

# Load the trained MobileNetV2 model once at startup
if os.path.exists(MODEL_PATH):
    print(f"Loading MobileNetV2 fire detection model from: {MODEL_PATH}")
    model = keras.models.load_model(MODEL_PATH)
else:
    print(f"Warning: MobileNetV2 model not found at {MODEL_PATH}. Make sure to run train_mobilenetv2.py first.")
    model = None

def predict_fire(image_path: str) -> float:
    """
    Predicts the probability of fire in an image.
    Returns:
        float: Probability score between 0.0 and 1.0 (higher means fire detected).
        None: If the image cannot be loaded or processed.
    """
    if model is None:
        print("Error: Fire detection model is not loaded.")
        return None

    try:
        # Load image with OpenCV
        img = cv2.imread(image_path)
        if img is None:
            print(f"Error: Could not load image at {image_path}")
            return None
        
        # Preprocess image to match MobileNetV2 model input
        img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        img = cv2.resize(img, (180, 180))
        img = np.array(img) / 255.0
        img = np.expand_dims(img, axis=0)
        
        # Run prediction
        # The model returns a single sigmoid probability: 0 (Non-Fire) to 1 (Fire)
        prediction = model.predict(img)
        return float(prediction[0][0])
    except Exception as e:
        print(f"Error during image inference: {e}")
        return None
