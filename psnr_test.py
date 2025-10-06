import cv2
import numpy as np
import os

# Function to calculate PSNR between two images
def calculate_psnr(original_image_path, stego_image_path):
    # Load the images
    original = cv2.imread(original_image_path)
    stego = cv2.imread(stego_image_path)

    # Check if the images have the same dimensions
    if original.shape != stego.shape:
        raise ValueError("The dimensions of the images do not match!")

    # Calculate Mean Squared Error (MSE)
    mse = np.mean((original - stego) ** 2)

    # If MSE is zero, images are identical
    if mse == 0:
        return float('inf')

    # Define the maximum pixel value for the image (typically 255 for 8-bit images)
    max_pixel_value = 255.0

    # Calculate PSNR
    psnr = 20 * np.log10(max_pixel_value / np.sqrt(mse))

    return psnr

def get_file_path():
    while True:
        file_path = input("Please enter the path to the file: ")
        
        # Check if the file exists
        if os.path.isfile(file_path):
            print("\n\t\t\tFile found!")
            return file_path
        else:
            print("\n\t\t\tFile not found. Please try again.")



# Paths to the original and steganography images
original_image_path = get_file_path()
stego_image_path = get_file_path()

# Call the function to calculate PSNR
psnr_value = calculate_psnr(original_image_path, stego_image_path)

print(f"PSNR between the original and stego image: {psnr_value} dB")
