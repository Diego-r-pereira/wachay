import numpy as np
import os
import pathlib
import cv2
import tensorflow as tf
import tf_keras as keras
from tf_keras.applications import MobileNetV2
from tf_keras.models import Model
from tf_keras.layers import Dense, Dropout, GlobalAveragePooling2D
from tf_keras.optimizers import Adam
from tf_keras.preprocessing.image import ImageDataGenerator
from tf_keras.callbacks import EarlyStopping, ReduceLROnPlateau

# Define directories relative to backend root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_FIRE_DIR = os.path.join(BASE_DIR, "assets", "img", "Data", "Train_Data", "Fire")
TRAIN_NON_FIRE_DIR = os.path.join(BASE_DIR, "assets", "img", "Data", "Train_Data", "Non_Fire")
TEST_FIRE_DIR = os.path.join(BASE_DIR, "assets", "img", "Data", "Test_Data", "Fire")
TEST_NON_FIRE_DIR = os.path.join(BASE_DIR, "assets", "img", "Data", "Test_Data", "Non_Fire")

def load_dataset(fire_path, non_fire_path, img_size=(180, 180)):
    X, y = [], []
    fire_dir = pathlib.Path(fire_path)
    non_fire_dir = pathlib.Path(non_fire_path)
    
    labels_map = {"Fire": 1, "NonFire": 0}
    
    # Load Fire images
    fire_images = list(fire_dir.glob("*.jpg")) + list(fire_dir.glob("*.png")) + list(fire_dir.glob("*.jpeg"))
    print(f"Loading {len(fire_images)} fire images from {fire_path}...")
    for img_path in fire_images:
        img = cv2.imread(str(img_path))
        if img is not None:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            img = cv2.resize(img, img_size)
            X.append(img)
            y.append(labels_map["Fire"])
            
    # Load NonFire images
    non_fire_images = list(non_fire_dir.glob("*.jpg")) + list(non_fire_dir.glob("*.png")) + list(non_fire_dir.glob("*.jpeg"))
    print(f"Loading {len(non_fire_images)} non-fire images from {non_fire_path}...")
    for img_path in non_fire_images:
        img = cv2.imread(str(img_path))
        if img is not None:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            img = cv2.resize(img, img_size)
            X.append(img)
            y.append(labels_map["NonFire"])
            
    return np.array(X), np.array(y)

def train():
    img_size = (180, 180)
    
    # 1. Load Data
    X_train, y_train = load_dataset(TRAIN_FIRE_DIR, TRAIN_NON_FIRE_DIR, img_size)
    X_val, y_val = load_dataset(TEST_FIRE_DIR, TEST_NON_FIRE_DIR, img_size)
    
    if len(X_train) == 0 or len(X_val) == 0:
        print("Error: No training or validation images found. Check directories.")
        return
    
    # Normalize pixel values
    X_train = X_train / 255.0
    X_val = X_val / 255.0
    
    print(f"Train dataset size: {X_train.shape}, labels: {y_train.shape}")
    print(f"Validation dataset size: {X_val.shape}, labels: {y_val.shape}")
    
    # 2. Build MobileNetV2 Model
    # Input shape: (180, 180, 3)
    base_model = MobileNetV2(weights="imagenet", include_top=False, input_shape=(180, 180, 3))
    
    # Freeze base model layers initially
    for layer in base_model.layers:
        layer.trainable = False
        
    x = base_model.output
    x = GlobalAveragePooling2D()(x)
    x = Dropout(0.3)(x)
    predictions = Dense(1, activation="sigmoid")(x)
    
    model = Model(inputs=base_model.input, outputs=predictions)
    
    # Compile model for initial training
    model.compile(optimizer=Adam(learning_rate=1e-3), loss="binary_crossentropy", metrics=["accuracy"])
    
    print("\nTraining top layers (warmup)...")
    early_stopping_warmup = EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True)
    model.fit(X_train, y_train, batch_size=32, epochs=10, validation_data=(X_val, y_val), callbacks=[early_stopping_warmup])
    
    # 3. Fine-tuning: Unfreeze top layers of base model
    print("\nUnfreezing top 30 layers for fine-tuning...")
    for layer in base_model.layers[-30:]:
        layer.trainable = True
        
    # Recompile with very low learning rate
    model.compile(optimizer=Adam(learning_rate=1e-5), loss="binary_crossentropy", metrics=["accuracy"])
    
    # Setup Data Augmentation
    datagen = ImageDataGenerator(
        rotation_range=15,
        width_shift_range=0.1,
        height_shift_range=0.1,
        shear_range=0.1,
        zoom_range=0.15,
        horizontal_flip=True,
        fill_mode="nearest"
    )
    
    # Callbacks
    early_stopping = EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True, verbose=1)
    reduce_lr = ReduceLROnPlateau(monitor="val_loss", factor=0.2, patience=3, min_lr=1e-7, verbose=1)
    
    print("\nStarting fine-tuning with data augmentation...")
    model.fit(
        datagen.flow(X_train, y_train, batch_size=32),
        epochs=15,
        validation_data=(X_val, y_val),
        callbacks=[early_stopping, reduce_lr]
    )
    
    # Save the model
    model_save_dir = os.path.join(BASE_DIR, "models")
    os.makedirs(model_save_dir, exist_ok=True)
    model_save_path = os.path.join(model_save_dir, "fire_detection_model_mobilenetv2.h5")
    
    # Save model in standard H5 format using tf_keras
    model.save(model_save_path)
    print(f"\nModel saved successfully at: {model_save_path}")

if __name__ == "__main__":
    train()
