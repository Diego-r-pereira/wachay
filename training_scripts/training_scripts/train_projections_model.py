import pandas as pd
import sqlite3
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
import joblib
import os
import json
from datetime import datetime
import numpy as np

# Define paths
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'wachay.db')
MODEL_DIR = os.path.join(BASE_DIR, 'models')
MODEL_PATH = os.path.join(MODEL_DIR, 'projections_model.pkl')
ASSETS_DIR = os.path.join(BASE_DIR, 'assets', 'data')
PREDICTIONS_PATH = os.path.join(ASSETS_DIR, 'predictions.json')


def generate_static_predictions(model):
    """
    Generates a grid of predictions for a static JSON file.
    """
    if not model:
        print("Model not available, skipping static prediction generation.")
        return

    print("Generating static predictions for heatmap...")

    # Bounding Box for the Santa Cruz de la Sierra region
    min_lat, max_lat = -18.2, -17.5
    min_lng, max_lng = -63.6, -62.8

    # Create a grid of points
    # We use np.linspace to create an evenly spaced grid
    lat_points = np.linspace(min_lat, max_lat, 100) # 100 points vertically
    lng_points = np.linspace(min_lng, max_lng, 100) # 100 points horizontally
    
    # Get current month and day_of_week for prediction
    current_date = datetime.now()
    current_month = current_date.month
    current_day_of_week = current_date.weekday() # Monday is 0 and Sunday is 6

    # Generate grid points for the DataFrame
    grid_points = []
    for lat in lat_points:
        for lng in lng_points:
            grid_points.append([lat, lng, current_month, current_day_of_week])

    if not grid_points:
        print("No grid points generated. Aborting prediction generation.")
        return

    # Create a DataFrame for prediction
    input_df = pd.DataFrame(grid_points, columns=['latitude', 'longitude', 'month', 'day_of_week'])

    # Predict risk scores
    try:
        risk_scores = model.predict(input_df)

        # Combine coordinates with risk scores
        heatmap_data = []
        for i in range(len(grid_points)):
            heatmap_data.append([grid_points[i][0], grid_points[i][1], float(risk_scores[i])])
        
        # Save to JSON file
        os.makedirs(ASSETS_DIR, exist_ok=True)
        with open(PREDICTIONS_PATH, 'w') as f:
            json.dump(heatmap_data, f)

        print(f"Successfully generated and saved {len(heatmap_data)} predictions to {PREDICTIONS_PATH}")

    except Exception as e:
        print(f"Error during static prediction generation: {e}")


def train_projections_model():
    """
    Connects to the database, loads report data, trains a RandomForest model
    to predict fire risk, and saves the trained model.
    """
    print("Starting model training process...")

    # --- 1. Load Data ---
    try:
        conn = sqlite3.connect(DB_PATH)
        # Load data, ignoring reports without location data
        query = "SELECT * FROM report WHERE latitude IS NOT NULL AND longitude IS NOT NULL"
        df = pd.read_sql_query(query, conn)
        conn.close()
        print(f"Successfully loaded {len(df)} records from the database.")
    except Exception as e:
        print(f"Error loading data from {DB_PATH}: {e}")
        return None

    if df.empty:
        print("No data with location information available to train the model. Aborting.")
        return None

    # --- 2. Feature Engineering & Preprocessing ---
    print("Preparing data for training...")
    # Convert detection_time to datetime objects
    df['detection_time'] = pd.to_datetime(df['detection_time'])

    # Extract temporal features
    df['month'] = df['detection_time'].dt.month
    df['day_of_week'] = df['detection_time'].dt.dayofweek # Monday=0, Sunday=6

    # For simplicity, we'll define 'fire_risk' based on severity and affected area.
    # This is a proxy for risk and can be refined.
    severity_map = {'Bajo': 1, 'Medio': 2, 'Alto': 3, 'Critico': 4}
    df['severity_numeric'] = df['severity_level'].map(severity_map).fillna(0)
    df['affected_area'] = df['affected_area'].fillna(0)
    
    # Target variable: A simple risk score
    # We give more weight to severity than to the area affected.
    df['risk_score'] = df['severity_numeric'] * 0.7 + df['affected_area'] * 0.3
    
    # Select features for the model
    # We will predict risk based on location and time
    features = ['latitude', 'longitude', 'month', 'day_of_week']
    target = 'risk_score'

    X = df[features]
    y = df[target]
    
    print(f"Features selected: {features}")
    print(f"Target variable: {target}")

    # --- 3. Model Training ---
    print("Splitting data and training model...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # We use a RandomForestRegressor, a good general-purpose model
    model = RandomForestRegressor(n_estimators=100, random_state=42, oob_score=True)
    model.fit(X_train, y_train)

    # Evaluate the model
    test_score = model.score(X_test, y_test)
    oob_score = model.oob_score_
    print(f"Model training complete.")
    print(f"Test Set R^2 Score: {test_score:.4f}")
    print(f"Out-of-Bag (OOB) Score: {oob_score:.4f}")

    # --- 4. Save Model ---
    print("Saving the trained model...")
    try:
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        print(f"Model successfully saved to {MODEL_PATH}")
        return model
    except Exception as e:
        print(f"Error saving model: {e}")
        return None

if __name__ == '__main__':
    trained_model = train_projections_model()
    generate_static_predictions(trained_model)
