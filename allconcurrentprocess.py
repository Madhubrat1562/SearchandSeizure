import serial
from picamera2 import Picamera2, Preview
# from picamera2.encoders import H264Encoder
# from picamera2.outputs import FfmpegOutput

from PIL import Image, ImageDraw, ImageFont

import time
import subprocess
import threading
import queue
import datetime
import cv2

import os
import requests
import numpy as np

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# Configure the serial port and baud rate
SERIAL_PORT = '/dev/ttyUSB2'  # Update with your actual serial port
BAUD_RATE = 115200  # Common baud rate for SIM7600G module

# Global variable for the serial connection
ser = None

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

def send_at_command(command, response_terminator='\r\n', timeout=10):
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

def setup_sms_mode():
    """
    Set the module to SMS text mode.
    """
    print("Setting SMS text mode...")
    response = send_at_command('AT+CMGF=1')
    print(response)
    
    response = send_at_command('AT+CPMS="SM","SM","SM"')
    print(response)
    
    # checking if gps works or not
    # response = send_at_command('AT+CMGD=1,4')
    # print(response)
    
    '''
    response = send_at_command('AT+CGPS=1')
    print(response)
    response = send_at_command('AT+CGPSINFO')
    print(response)
    response = send_at_command('AT+CGPS=0')
    print(response)
    '''

def check_for_start(msg):
    # more conditions can be aded later
    return "start" in msg.lower()
    
def check_for_stop(msg):
    # more conditions can be aded later
    return "stop" in msg.lower()

def read_sms():
    """
    Read the latest unread SMS message from the module.
    """
    #print("Checking for unread SMS messages...")
    
    # List all messages with their indices and statuses
    response = send_at_command('AT+CMGL="ALL"')
    
    print('Length of response:',len(response))
    # print('Type of response:',type(response))
    # print('Response:\n',response)
    
    liss = response.splitlines()
    # print('Items in list:')
    
    '''
    for item in liss:
        print('Length of item:',len(item),'and item:',item)
    '''
        
    idx = -1 + len(liss)
    while idx >=0 and not liss[idx].startswith("+CMGL:"):
        idx -= 1
    idx += 1
        
    if idx < len(liss):
        print('idx<len(liss) and len[liss] =',liss[idx])
        
        if check_for_start(liss[idx]):
            return "start"
        elif check_for_stop(liss[idx]):
            return "stop"
    
    return "nil"
    
def sms_thread(comQ):
    try:
        while True:
            rsp = read_sms()
            
            if rsp != "nil":
                comQ.put(rsp)
    
    except Exception as e:
        print(f"An error occurred: {e}")
    
    finally:
        # Ensure the serial connection is closed properly
        if ser and ser.is_open:
            ser.close()
        print("Serial connection closed.")

# Function to add text overlay
def add_text_overlay(frame, text, position=(10, 10), font_size=20):
    
    # Convert frame to PIL Image
    image = Image.fromarray(frame)
    draw = ImageDraw.Draw(image)
    
    # Use a default PIL font
    font = ImageFont.load_default()
    
    draw.text(position, text, font=font, fill=(255, 255, 255))
    
    return np.array(image)

def video_thread(comQ, comQQ):
    try:
        picam2 = Picamera2()
     
        # preview_config = picam2.create_preview_configuration()
        # picam2.configure(preview_config)
        picam2.configure(picam2.create_video_configuration(main={"size": (640, 480)}))
         
        # picam2.start_preview(Preview.QTGL)
        # encoder = H264Encoder(10000000)

        picam2.start()
        
        # fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        
        print('Camera started and ready to record.')
        nect = 0
        
        isRecording = 0
        
        currentFileName = 'nil'
        startMinute = 0
        
        while True:
            nect += 1
            nect %= 7*10**6
            if nect == 0:
                print('Camera loop')
            
            currentMinute = int(datetime.datetime.now().minute)
            
            msg = None
            if not comQ.empty():
                msg = comQ.get()
            
            if msg != None or isRecording == 1:
                if msg == "start" and isRecording == 0:
                    startMinute = int(datetime.datetime.now().minute)
                    
                    isRecording = 1
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
                    
                    # video_output = FfmpegOutput(fileName)
                    # picam2.start_recording(encoder,output=video_output)
                    fourcc = cv2.VideoWriter_fourcc(*"mp4")
                    
                    videoOutputSaver = cv2.VideoWriter(fileName, fourcc, 30.0, (640, 480))
                    
                    print('Camera started recording')
                    
                elif ( msg == "stop" or min( abs(currentMinute - startMinute), 60 - abs(currentMinute - startMinute) ) > 0 ) and isRecording == 1:
                    isRecording = 0
                    
                    videoOutputSaver.release()
                    
                    # picam2.stop_recording()
                    # watermarkVideo(currentFileName)
                    
                    # comQQ.put(currentFileName) # if needed comment this, so video won't get sent
                    
                    print('Camera stopped recording')
            
            if isRecording == 1:
                INSPECTOR_ID = 'Inspector_5503'
                frame = picam2.capture_array()
                current_time = datetime.datetime.now()
                
                response = requests.get('https://get.geojs.io/v1/ip/geo.json')
                data = response.json()
                
                hour, minute, sec = int(current_time.hour), int(current_time.minute), int(current_time.second)
                
                minute += 30
                if minute > 60: hour += 1
                minute %= 60
                
                hour += 5
                
                hour %= 24
                hour %= 12
                
                nowtime = str(current_time.day) + '-' + str(current_time.month) + '-' + str(current_time.year) + ', ' + str(hour) + ':' + str(minute) + ':' + str(sec)
                
                overlay_text = f"Inspector ID: {INSPECTOR_ID} \nCurrent Time: {nowtime} \nLocation: {data['latitude']}, {data['longitude']} \nRegion: {data['region']}"
                
                frame_with_overlay = add_text_overlay(frame, overlay_text)
                
                videoOutputSaver.write(frame_with_overlay)
    
    except Exception as e:
        print(f"An error occurred: {e}")     
    finally:
        cv2.destroyAllWindows()
        
        picam2.stop()
        picam2.close()
        
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

def transmission_thread(comQ):
    try:
        SERVER_ADDRESS = 'https://c133-47-9-113-234.ngrok-free.app'
        
        public_key_filename = 'public_key.pem'
        print('Video transmission thread active.')
        nect = 0
        
        while True:
            nect += 1
            nect %= 7*10**6
            if nect == 0:
                print('Transmission loop.')
                
            if not comQ.empty():
                video_filename = comQ.get()
                
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
                
    except Exception as e:
        print(f"An error occurred: {e}")
    
def main():
    global ser
    
    # First kill the interfering processes
    kill_processes_using_device(SERIAL_PORT)
    
    # Initialize the serial connection
    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
        setup_sms_mode()
    except serial.SerialException as e:
        print(f"Error opening serial port: {e}")
        return
    
    comQ1, comQ2 = queue.Queue(), queue.Queue()
    
    # Create and start threads
    thread1 = threading.Thread(target=sms_thread, args=(comQ1,))
    thread2 = threading.Thread(target=video_thread, args=(comQ1,comQ2,))
    thread3 = threading.Thread(target=transmission_thread, args=(comQ2,))
    
    thread1.start()
    thread2.start()
    thread3.start()
    
    # Join threads (optional, if you want to wait for them to finish)
    thread1.join()
    thread2.join()
    thread3.join()

if __name__ == "__main__":
    main()
