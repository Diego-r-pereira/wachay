import numpy as np
import os
import pathlib
import cv2
import tensorflow as tf
from tensorflow import keras
from sklearn.model_selection import train_test_split

# This script is for training the model based on the Google Colab notebook.
# It is not part of the web application itself.

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

X_train, X_test, y_train, y_test = train_test_split(X_samp, y_samp, test_size=0.2, random_state=42)

# Data Augmentation
data_argumentation = keras.Sequential([
    keras.layers.RandomContrast(0.3),
    keras.layers.RandomRotation(0.2),
    keras.layers.RandomZoom(0.5)
])

# Model Architecture from the notebook
model = keras.Sequential([
    data_argumentation,
    keras.layers.Conv2D(64, (3,3), padding='same', activation="relu", input_shape=(180, 180, 3)),
    keras.layers.MaxPooling2D(),
    keras.layers.Conv2D(32, (3,3), padding='same', activation="softmax"),
    keras.layers.MaxPooling2D(),
    keras.layers.Conv2D(16, (3,3), padding='same', activation="softmax"),
    keras.layers.MaxPooling2D(),
    keras.layers.Dropout(0.2),
    keras.layers.Flatten(),
    keras.layers.Dense(10, activation="sigmoid"),
    keras.layers.Dense(1, activation="sigmoid")
])

# Compile the model
model.compile(optimizer="adam", loss='binary_crossentropy', metrics=["accuracy"])

# Train the model
model.fit(X_train, y_train, epochs=4)

# Save the model
model.save('models/fire_model_google.h5')
print("Model trained based on Google Colab notebook and saved as models/fire_model_google.h5")
