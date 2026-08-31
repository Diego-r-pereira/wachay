import numpy as np
import os
import pathlib
import cv2
import tensorflow as tf
from tensorflow import keras
from sklearn.model_selection import train_test_split
from tensorflow.keras.applications import EfficientNetV2B0
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Dense, Flatten, Dropout, GlobalAveragePooling2D
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.preprocessing.image import ImageDataGenerator
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

# This script is for fine-tuning the EfficientNetV2B0 model.

# Data paths
fire_image_path = "assets/img/Data/Train_Data/Fire"
non_fire_path = "assets/img/Data/Train_Data/Non_Fire"
fire_image_path = pathlib.Path(fire_image_path)
non_fire_path = pathlib.Path(non_fire_path)

# Preprocessing
train_data_images = {
    "Fire": list(fire_image_path.glob("*.jpg")) + list(fire_image_path.glob("*.png")),
    "NonFire": list(non_fire_path.glob("*.jpg")) + list(non_fire_path.glob("*.png"))
}
train_labels = {
    "Fire": 0,
    "NonFire": 1
}

X, y = [], []
print("Loading images...")
for label, images in train_data_images.items():
    for image in images:
        img = cv2.imread(str(image))
        if img is not None:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            img = cv2.resize(img, (224, 224))
            X.append(img)
            y.append(train_labels[label])

X_samp = np.array(X)
y_samp = np.array(y)

X_samp = (X_samp / 255.0) # Normalize pixel values

X_train, X_test, y_train, y_test = train_test_split(X_samp, y_samp, test_size=0.2, random_state=42, stratify=y_samp)

# Load EfficientNetV2B0 model pre-trained on ImageNet, without its top classification layer
base_model = EfficientNetV2B0(weights='imagenet', include_top=False, input_shape=(224, 224, 3))

# First, train only the top layers
for layer in base_model.layers:
    layer.trainable = False

x = base_model.output
x = GlobalAveragePooling2D()(x) # Use GlobalAveragePooling2D for modern CNNs
x = Dropout(0.3)(x) # Adjusted dropout
predictions = Dense(1, activation='sigmoid')(x)

model = Model(inputs=base_model.input, outputs=predictions)

model.compile(optimizer="adam", loss='binary_crossentropy', metrics=["accuracy"])

print("\nTraining the top layers...")
initial_early_stopping = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
model.fit(X_train, y_train, epochs=25, validation_data=(X_test, y_test), callbacks=[initial_early_stopping])


# --- Enhanced Fine-Tuning ---

# 1. Data Augmentation
print("\nPreparing for data augmentation...")
datagen = ImageDataGenerator(
    rotation_range=20,
    width_shift_range=0.2,
    height_shift_range=0.2,
    shear_range=0.2,
    zoom_range=0.2,
    horizontal_flip=True,
    fill_mode='nearest'
)

# 2. Unfreeze more layers for deeper fine-tuning
print("Unfreezing the top 20 layers for fine-tuning...")
for layer in base_model.layers[-20:]:
    layer.trainable = True


# Re-compile the model with a very low learning rate for fine-tuning
model.compile(optimizer=Adam(learning_rate=1e-5), loss='binary_crossentropy', metrics=["accuracy"])

# 3. Callbacks for smart training
print("Setting up EarlyStopping and ReduceLROnPlateau callbacks...")
early_stopping = EarlyStopping(
    monitor='val_loss',
    patience=10,  # Stop after 10 epochs of no improvement
    verbose=1,
    restore_best_weights=True  # Restore model weights from the epoch with the best val_loss
)
reduce_lr = ReduceLROnPlateau(
    monitor='val_loss',
    factor=0.2,  # Reduce learning rate by a factor of 0.2
    patience=5,   # Reduce learning rate after 5 epochs of no improvement
    verbose=1,
    min_lr=1e-6   # Minimum learning rate
)

print("\nStarting enhanced fine-tuning with data augmentation and callbacks...")
# Train with the data generator and callbacks
# We set a high number of epochs, but EarlyStopping will find the optimal number
history = model.fit(
    datagen.flow(X_train, y_train, batch_size=32),
    epochs=50,
    validation_data=(X_test, y_test),
    callbacks=[early_stopping, reduce_lr]
)

# Save the fine-tuned model with a new name
model.save('models/fire_detection_model_efficientnet_v2.h5')
print("\nModel fine-tuned and saved as models/fire_detection_model_efficientnet_v2.h5")
