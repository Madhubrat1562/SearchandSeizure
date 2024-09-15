import requests
import time
import datetime
import cv2
import subprocess
import serial

import numpy as np
import os

from picamera2 import Picamera2
from PIL import Image, ImageDraw, ImageFont

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# global ser object
ser = None

# Configure the serial port and baud rate
SERIAL_PORT = '/dev/ttyUSB2'  # Update with your actual serial port
BAUD_RATE = 115200  # Common baud rate for SIM7600G module

def kill_processes_using_device(device_path):
    """
    Find and kill all processes using the specified device file.
    
    :param device_path: Path to the device file, e.g., '/dev/ttyUSB2'
    """
    try:
        # Use lsof to list processes using the device file
        result = subprocess.run(['sudo', 'lsof', device_path], capture_output=True, text=True, check=True)
        output = result.stdout
        
        print("Output text:\n", output)
        
        # Process the output to extract PIDs
        lines = output.splitlines()
        pids = set()
        for line in lines:
            if line.startswith('COMMAND'):
                continue
            parts = line.split()
            if len(parts) > 1:
                pid = parts[1]
                pids.add(pid)
        
        if not pids:
            print(f"No processes found using {device_path}.")
            return
        
        # Kill each process
        for pid in pids:
            print(f"Killing process {pid}...")
            subprocess.run(['sudo', 'kill', '-9', pid], check=True)
            print(f"Process {pid} killed.")
        
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
       
def send_at_command(command, response_terminator='\r\n', timeout=5):
    """
    Send an AT command to the SIM7600G module and return the response.
    """
    global ser
    ser.write((command + '\r').encode())
    start_time = time.time()
    response = ""
    
    while True:
        if ser.in_waiting:
            response += ser.read(ser.in_waiting).decode()
            if response_terminator in response:
                break
        if time.time() - start_time > timeout:
            break
    
    return response

# Load the RSA public key from a file
def load_public_key(filename):
    with open(filename, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

# Compute the SHA-256 hash of a video file
def compute_file_hash(filename):
    hash_algo = hashes.Hash(hashes.SHA256())
    with open(filename, 'rb') as file:
        while chunk := file.read(8192):
            hash_algo.update(chunk)
    return hash_algo.finalize()

# Encrypt the hash using the RSA public key
def encrypt_hash(public_key, hash_value):
    encrypted_hash = public_key.encrypt(
        hash_value,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_hash

def add_text_overlay(frame, text, position=(10, 10), font_size=20):
    
    # Convert frame to PIL Image
    image = Image.fromarray(frame)
    draw = ImageDraw.Draw(image)
    
    # Use a default PIL font
    font = ImageFont.load_default()
    
    draw.text(position, text, font=font, fill=(255, 255, 255))
    
    return np.array(image)
    
def video_recording_and_sending():
    # Initialize the camera
    picam2 = Picamera2()
    picam2.configure(picam2.create_video_configuration(main={"size": (640, 480)}))

    # Start the camera
    picam2.start()

    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    
    isRecording = 0
    
    prevLogSize = 0
    prevLog = []
    currentFileName = 'nil'
    
    if os.path.isfile( os.path.join( os.getcwd(), 'minicom_log.log') ):
        with open('minicom_log.log') as f:
            prevLog = f.read().splitlines()
            prevLogSize = len(prevLog)
    
    videoOutputSaver = None
    
    data = []
    
    FRAME_CNT = 0
    NO_OF_VIDEOS = 0
    
    # while True:
    while NO_OF_VIDEOS == 0:
        log = []
        if os.path.isfile( os.path.join( os.getcwd(), 'minicom_log.log') ):
            with open('minicom_log.log') as f:
                log = f.read().splitlines()

        idx = -1 + len(log)
        while idx >= 0 and not log[idx].startswith('+CMTI:'): idx -= 1

        if idx >= prevLogSize and idx < len(log) and log[idx].startswith('+CMTI:'):
            # print(log)

            isRecording = not isRecording

            prevLog = log
            prevLogSize = len(log)

            if isRecording == 1:
    
                cnt = -1

                fileName = 'evidence'
                with open('video_count.txt') as f:
                    r = int(f.read().strip())

                    fileName += str(r)
                    cnt = r + 1

                if cnt > 0:
                    with open('video_count.txt','w') as f:
                        f.write(str(cnt))

                fileName += '.mp4'
                currentFileName = fileName

                response = requests.get('https://get.geojs.io/v1/ip/geo.json')
                data = response.json()

                frame_rate = 30.0
                videoOutputSaver = cv2.VideoWriter(currentFileName, fourcc, frame_rate, (640, 480))

                print('Video',currentFileName,'recording started.')
                FRAME_CNT = 0
    
            else:
                print('Video',currentFileName,'recording stopped')
                NO_OF_VIDEOS += 1
			
                videoOutputSaver.release()
			
                SERVER_ADDRESS = 'https://bf6c-47-9-113-24.ngrok-free.app'
                public_key_filename = 'public_key.pem'

                video_filename = currentFileName
	
		# Load the public key
                public_key = load_public_key(public_key_filename)
	
		# Compute the hash of the video file
                file_hash = compute_file_hash(video_filename)
	
		# Encrypt the hash
                encrypted_hash = encrypt_hash(public_key, file_hash)
	
                idx = -1 + len(video_filename)
                while idx >= 0 and video_filename[idx] != '.': idx -= 1
	
                hash_filename = 'encrypted_videohash_' + video_filename[:idx] + '.bin'
	
                with open(hash_filename, 'wb') as enc_file:
                    enc_file.write(encrypted_hash)
	
                with open(video_filename, 'rb') as f:
                    files = {'file': (video_filename, f, 'video/mp4')}

                    # Send a POST request with the video file
                    response = requests.post(SERVER_ADDRESS, files=files)

                    # Print the response status and content
                    print("Status Code for video:", response.status_code)
                    print("Response Text:", response.text)

                with open(hash_filename, 'rb') as f:
                    files = {'file': (hash_filename, f, 'application/octet-stream')}

                    # Send a POST request with the video file
                    response = requests.post(SERVER_ADDRESS, files=files)

                    # Print the response status and content
                    print("Status Code for encrypted video hash:", response.status_code)
                    print("Response Text:", response.text)

        if isRecording == 1 :

            INSPECTOR_ID = 'Officer_5503'
            CASE_ID = 'Case-ID'

            frame = picam2.capture_array()
            current_time = datetime.datetime.now()
    
            # Convert frame to BGR format (if necessary)
            if frame.shape[2] == 4:  # If the frame has an alpha channel
                frame = cv2.cvtColor(frame, cv2.COLOR_RGBA2BGR)
            elif frame.shape[2] == 3:  # If the frame is in RGB format
                frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)

            hour, minute, sec = int(current_time.hour), int(current_time.minute), int(current_time.second)

            nowtime = str(current_time.day) + '-' + str(current_time.month) + '-' + str(current_time.year) + ', ' + str(hour) + ':' + str(minute) + ':' + str(sec)
    
            overlay_text = f"Officer ID: {INSPECTOR_ID} \nCase ID: {CASE_ID} \nCurrent Time: {nowtime} \nLocation: {data['latitude']}, {data['longitude']} \nRegion: {data['region']}"
    
            frame_with_overlay = add_text_overlay(frame, overlay_text)
    
            if videoOutputSaver != None:
                videoOutputSaver.write(frame_with_overlay)
    
            FRAME_CNT += 1
            # print('Captured frame',FRAME_CNT)

def main():
        global ser

        video_recording_and_sending()

        kill_processes_using_device('/dev/ttyUSB2')
        
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
        send_at_command('AT+CMGD=0,4')

        PHONE_NUM = '6387214522'
        message = 'Video and encrypted hash sent successfully.'

        send_at_command('AT+CMGF=1')
        send_at_command(f'AT+CMGS="{PHONE_NUM}"')

        ser.write((message + '\x1A').encode())

        if ser and ser.is_open:
            ser.close()

        os.remove('minicom_log.log')

if __name__ == '__main__':
        main()
