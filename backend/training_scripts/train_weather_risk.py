import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
import joblib
import os

# Define path to save model
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "weather_risk_model.pkl")

def generate_synthetic_weather_data(num_samples=5000):
    """
    Generates a synthetic dataset for fire risk index training based on weather telemetery:
    - Temperature (T): 10 to 45 degrees Celsius
    - Relative Humidity (RH): 10% to 100%
    - Wind Speed (W): 0 to 60 km/h
    
    Target:
    - Fire Risk Index: 0.0 (low) to 1.0 (critical)
    """
    np.random.seed(42)
    
    # Generate features
    temperature = np.random.uniform(10, 45, num_samples)
    humidity = np.random.uniform(10, 100, num_samples)
    wind_speed = np.random.uniform(0, 60, num_samples)
    
    # Fire Weather Index (FWI) proxy formula:
    # - Risk increases with high temp, low humidity, and high wind speed.
    # Normalize features to [0, 1] range for the formula contribution
    t_norm = (temperature - 10) / (45 - 10)
    rh_norm = (100 - humidity) / (100 - 10)  # low humidity = high risk
    w_norm = wind_speed / 60
    
    # Weighted contribution: 40% temp, 35% humidity, 25% wind
    risk_score = 0.40 * t_norm + 0.35 * rh_norm + 0.25 * w_norm
    
    # Add random Gaussian noise to simulate real-world variance
    noise = np.random.normal(0, 0.05, num_samples)
    risk_score = risk_score + noise
    
    # Clip risk score between 0.0 and 1.0
    risk_score = np.clip(risk_score, 0.0, 1.0)
    
    # Create DataFrame
    data = pd.DataFrame({
        "temperature": temperature,
        "humidity": humidity,
        "wind_speed": wind_speed,
        "risk_index": risk_score
    })
    
    return data

def train_weather_risk_model():
    print("Generating synthetic weather fire-risk dataset...")
    df = generate_synthetic_weather_data(5000)
    
    features = ["temperature", "humidity", "wind_speed"]
    target = "risk_index"
    
    X = df[features]
    y = df[target]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training RandomForestRegressor model...")
    # Train Random Forest Regressor
    model = RandomForestRegressor(n_estimators=100, random_state=42, oob_score=True)
    model.fit(X_train, y_train)
    
    # Evaluate
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    oob_score = model.oob_score_
    
    print(f"Training R^2 Score: {train_score:.4f}")
    print(f"Test R^2 Score: {test_score:.4f}")
    print(f"Out-of-Bag (OOB) Score: {oob_score:.4f}")
    
    # Save model
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Weather fire-risk model successfully saved to: {MODEL_PATH}")

if __name__ == "__main__":
    train_weather_risk_model()
