import numpy as np
import cv2
import tensorflow as tf
import pathlib
from IPython.display import display, HTML
import random

# Load the pre-trained model
model = tf.keras.models.load_model('fire_detection_model.h5')

def predict_image(image_path):
    """
    Predicts if an image contains fire or not.
    """
    img = cv2.imread(str(image_path))
    if img is not None:
        img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        img = cv2.resize(img, (180, 180))
        img = np.array(img) / 255.0
        img = np.expand_dims(img, axis=0)
        prediction = model.predict(img)
        return prediction[0][0]
    return None

def get_random_coordinates():
    """
    Generates random latitude and longitude.
    """
    lat = random.uniform(-90, 90)
    lon = random.uniform(-180, 180)
    return lat, lon

def get_google_maps_link(lat, lon):
    """
    Creates a Google Maps link from latitude and longitude.
    """
    return f'https://www.google.com/maps?q={lat},{lon}'