# Encrypt and decrypt an image via AES CBC mode.
# Inspired by https://github.com/RetlavSource/
# Note: It has message authentication (authenticated encryption).
import sys
import time
import cv2
import hashlib
import numpy as np
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from mimetypes import MimeTypes


def checkIfImage(filePath: str):
    """Check if file is image type or not."""
    if os.path.exists(filePath):
        mimeType = MimeTypes().guess_type(filePath)[0]
        if mimeType:
            mimeType = mimeType.split("/")[0]
        else:
            return False
        return True if(mimeType == "image") else False
    else:
        print("File does not exit")

def checkIfTxt(filePath: str):
    """Check if file is txt type or not."""
    if os.path.exists(filePath):
        mimeType = MimeTypes().guess_type(filePath)[0]
        if mimeType:
            mimeType = mimeType.split("/")[0]
        else:
            return False
        return True if(mimeType == "text") else False
    else:
        print("File does not exit")

def get_image(header_name, file_path):
    # Load original image from "images/original/imageToCypher.jpeg"
    image_orig = cv2.imread(file_path)
    row_orig, column_orig, depth_orig = image_orig.shape

    min_width = (AES.block_size + AES.block_size) // depth_orig + 1
    if column_orig < min_width:
        print(f'The minimum width of the image must be {min_width} pixels, so that IV and padding can be stored in a single additional row!')
        sys.exit()

    # Display original image
    cv2.imshow(header_name, image_orig)
    cv2.waitKey()
    return image_orig

def encrypt(dirPath, image_original, initialization_vector_size, password):
    # This program encrypts a jpg With AES-256. The encrypted image contains more data than the original image (e.g. because of 
    # padding, IV etc.). Therefore the encrypted image has one row more.

    # Load original image
    rowOrig, columnOrig, depthOrig = image_original.shape

    # Convert original image data to bytes
    imageOrigBytes = image_original.tobytes()

    # encrypt password
    # password = "ThisisAPasswordVaryGoodAndEvenBetterOne"
    hash = hashlib.sha256(password.encode())
    digested = hash.digest()
    key = digested
    iv = digested.ljust(initialization_vector_size)[:initialization_vector_size]

    # Encrypt
    cipher = AES.new(key, AES.MODE_GCM, iv)
    imageOrigBytesPadded = pad(imageOrigBytes, AES.block_size)
    ciphertext, authTag = cipher.encrypt_and_digest(imageOrigBytesPadded)
    nonceVal = cipher.nonce
    # Package authTag and nonceVal as list in prep for writing as .txt file.
    supportingData = [authTag, nonceVal]
    print("Supported data: ", supportingData)
    supportingData = [authTag.hex(), nonceVal.hex()]
    
    # Convert ciphertext bytes to encrypted image data
    #    The additional row contains columnOrig * DepthOrig bytes. Of this, ivSize + paddedSize bytes are used 
    #    void = columnOrig * DepthOrig - ivSize - paddedSize bytes unused
    paddedSize = len(imageOrigBytesPadded) - len(imageOrigBytes)
    void = columnOrig * depthOrig - initialization_vector_size - paddedSize
    ivCiphertextVoid = iv + ciphertext + bytes(void)
    imageEncrypted = np.frombuffer(ivCiphertextVoid, dtype = image_original.dtype).reshape(rowOrig + 1, columnOrig, depthOrig)

    # Create dir if not existing.
    if not os.path.exists(dirPath):
        os.makedirs(dirPath)

    # Saving encrypted image
    timestamp = str(int(time.time()))
    image_name = f"encryptedImg_AES_GCM_{timestamp}.bmp"
    cv2.imwrite(f"{dirPath}/{image_name}", imageEncrypted)
    print(f"Image saved in '{dirPath}' folder, with name: {image_name}")
    # Write supportingData
    supportedData_name = f"encryptedImg_AES_GCM_{timestamp}.txt"
    with open(dirPath + supportedData_name, 'w') as f:
        f.writelines('\n'.join(supportingData))

    # Display encrypted image
    cv2.imshow("Encrypted image", imageEncrypted)
    cv2.waitKey()

    # Save the encrypted image (optional)
    #    If the encrypted image is to be stored, a format must be chosen that does not change the data. Otherwise, 
    #    decryption is not possible after loading the encrypted image. bmp does not change the data, but jpg does. 

    # Close all windows
    cv2.destroyAllWindows()


def decrypt(dirPath, imageEncrypted, supportingData, initialization_vector_size, password):
    # Password used for encryption.
    hash = hashlib.sha256(password.encode())
    key = hash.digest()

    # Convert encrypted image data to ciphertext bytes
    rowEncrypted, columnOrig, depthOrig = imageEncrypted.shape 
    rowOrig = rowEncrypted - 1
    encryptedBytes = imageEncrypted.tobytes()
    iv = encryptedBytes[:initialization_vector_size]
    imageOrigBytesSize = rowOrig * columnOrig * depthOrig
    paddedSize = (imageOrigBytesSize // AES.block_size + 1) * AES.block_size - imageOrigBytesSize
    encrypted = encryptedBytes[initialization_vector_size : initialization_vector_size + imageOrigBytesSize + paddedSize]

    # Decrypt
    cipher = AES.new(key, AES.MODE_GCM, iv, nonce=supportingData[1])
    decryptedImageBytesPadded = cipher.decrypt_and_verify(encrypted, supportingData[0])
    decryptedImageBytes = unpad(decryptedImageBytesPadded, AES.block_size)

    # Convert bytes to decrypted image data
    decryptedImage = np.frombuffer(decryptedImageBytes, imageEncrypted.dtype).reshape(rowOrig, columnOrig, depthOrig)

    # Saving decrypted image
    image_name = f"decryptedImg_AES_CBC_{str(int(time.time()))}.jpg"
    cv2.imwrite(f"{dirPath}/{image_name}", decryptedImage)
    print(f"Image saved in '{dirPath}' folder, with name: {image_name}")

    # Display decrypted image
    cv2.imshow("Decrypted Image", decryptedImage)
    cv2.waitKey()

    # Close all windows
    cv2.destroyAllWindows()

def main():
    print("Image encryption and decryption program running.")
    # Set sizes
    #keySize = 32
    initialization_vector_size = AES.block_size
    # Useful directories.
    imgDir = "images/"
    #originalImgPath = imgDir +'gifts.jpg'
    encryptedImgDir = imgDir +'encrypted/'
    decryptedImgDir = imgDir +'decrypted/'
    userChoice = int(input("""
        Select operation to execute:
            1. Encrypt an image using AES_GCM
            2. Decrypt the image using AES_GCM
            3. Exist program
        """))
    if userChoice == 1:
        originalImgPath = input(r'Enter path of image to encrypt: ')
        print("Path of image to encrypt: ", originalImgPath)
        imgStatus = checkIfImage(originalImgPath)
        if imgStatus == True:
            print("Image file found. Proceeding...")
            print('\nEncrypting image using AES_GCM...')
            keyAsPassword = str(input('Enter image encryption key : '))
            origImageRead = get_image("Original Image", originalImgPath)
            print('\nEncrypting...')
            encrypt(encryptedImgDir, origImageRead, initialization_vector_size, keyAsPassword)
            print("Image encryption done.")
        else: 
            print("File is not an image file.")
    elif userChoice == 2:
        # Get file timestamp.
        # ts = str(1692343895) # For now.
        # encFilefullFilename = encryptedImgDir + "encryptedImg_AES_CBC_" + ts + ".bmp"
        encFilefullFilename = input(r'Enter path of encrypted image : ')
        print("Path of encrypted image: ", encFilefullFilename)
        imgStatus = checkIfImage(encFilefullFilename)
        if imgStatus == True: # To be improved to enforce check that it is encrypted image file.
            keyAsPassword = str(input('Enter image encryption key : '))
            # Get path to supporting data.
            supportingFilefullFilename = input(r'Enter path to supporting data : ')
            txtStatus = checkIfTxt(supportingFilefullFilename)
            if txtStatus == True:
                # Read image file.
                readEncImgFile = get_image("Encrypted Image", encFilefullFilename)
                # Read text file.
                with open(supportingFilefullFilename) as f:
                    lines = f.readlines()
                dataSupport = [bytes.fromhex(lines[0]), bytes.fromhex(lines[1])]
                print('\nDecrypting image using AES_GCM...')
                decrypt(decryptedImgDir, readEncImgFile, dataSupport, initialization_vector_size, keyAsPassword)
            else: 
                print("Specified path is not a text supporting file.")
        else: 
            print("Specified path is not an encrypted image file.")
    elif userChoice == 3:
        print('Exiting program. Thank you.')
        sys.exit()
    else:
        print('!!!Invalid option selected.!!!')
        sys.exit()


if __name__== "__main__":
      main()