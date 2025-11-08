from PIL import Image
import os

# Create the directory if it doesn't exist
output_dir = "static/images/carousel"
os.makedirs(output_dir, exist_ok=True)

# Create 50 placeholder images
for i in range(1, 51):
    # Create a 250x250 image with a random color
    img = Image.new('RGB', (250, 250), color = 'red' if i % 2 == 0 else 'green')
    img.save(os.path.join(output_dir, f'{i}.jpg'))

print("50 placeholder images created.")
