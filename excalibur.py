import asyncio
import base64
import hashlib
import json
import os
import aiohttp
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import classification_report
import pyfiglet

# VirusTotal API Key
API_KEY = 'api key'  # Replace with your actual API key
BASE_URL = 'https://www.virustotal.com/api/v3/'

# Load and prepare dataset for training
def load_malicious_url_dataset(file_path):
    df = pd.read_csv(file_path)
    # Strip any leading/trailing spaces from column names
    df.columns = df.columns.str.strip()
    print("Columns in the dataset:", df.columns.tolist())  # Print the columns to check
    print("First few rows of the dataset:")
    print(df.head())  # Print the first few rows to check the data
    return df

def preprocess_data(df):
    # Ensure the 'type' column exists
    if 'type' not in df.columns:
        raise ValueError("The dataset does not contain a 'type' column. Available columns: " + str(df.columns))
    
    # Convert labels to numeric values (0: benign, 1: phishing, 2: defacement)
    df['label'] = df['type'].apply(lambda x: 0 if x == 'benign' else (1 if x == 'phishing' else 2))
    
    # Separate features and labels
    X = df['url']  # Use the URL as the feature
    y = df['label']
    
    print("Features shape:", X.shape)
    print("Labels shape:", y.shape)
    
    return X, y

def train_model(X, y):
    # Convert URLs to a DataFrame (this ensures a 2D structure with a column name)
    X = pd.DataFrame(X, columns=['url'])
    
    # Create a pipeline with OneHotEncoder and Logistic Regression
    model = make_pipeline(OneHotEncoder(handle_unknown='ignore'), LogisticRegression(max_iter=1000))
    
    # Split the dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    return model

# Load dataset and train model
df = load_malicious_url_dataset('malicious_urls.csv')  # Replace with your dataset path
X, y = preprocess_data(df)
model = train_model(X, y)

# AI Analysis based on VirusTotal result
def ai_file_analysis(vt_result):
    # Get the detection ratio from VirusTotal result
    if 'data' in vt_result and 'attributes' in vt_result['data']:
        detection_ratio = vt_result['data']['attributes'].get('last_analysis_stats', {}).get('malicious', 0)
        total_engines = vt_result['data']['attributes'].get('last_analysis_stats', {}).get('total', 0)

        # If detection ratio is higher than a threshold (e.g., 50% malicious detections), classify as malicious
        if total_engines > 0 and detection_ratio / total_engines > 0.5:
            return "malicious"
        else:
            return "safe"
    return "safe"  # Default to safe if no malicious data is found

# Async function to scan a file by hash using VirusTotal and predict safety
async def scan_file(session, file_hash):
    headers = {'x-apikey': API_KEY}
    async with session.get(f'{BASE_URL}files/{file_hash}', headers=headers) as response:
        result = await response.json()
        
        if response.status == 404:
            print(f"Error: File with hash {file_hash} not found in VirusTotal database.")
            return None
        elif response.status == 403:
            print("Error: API Key is invalid or rate-limited. Please check your API key.")
            return None
        elif response.status == 200:
            # Get AI prediction of the file
            prediction = ai_file_analysis(result)
            print(f"AI Prediction: {prediction}")  # Output the AI prediction clearly
            return result
        else:
            print(f"Unexpected error: {response.status}")
            return None

# Async function to scan a URL using VirusTotal
async def scan_url(session, url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {'x-apikey': API_KEY}
    async with session.get(f'{BASE_URL}urls/{url_id}', headers=headers) as response:
        result = await response.json()
        return result

# Function to get the SHA-256 hash of a file
def get_file_hash(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

# AI Analysis using the trained model for URLs
def ai_analysis(url):
    # Reshape the input to a 2D array before passing to the model
    prediction = model.predict(pd.DataFrame({'url': [url]}))  # Create a DataFrame with the correct shape
    return "safe" if prediction[0] == 0 else "malicious"

# Asynchronous function to handle multiple requests concurrently (if needed)
async def scan_multiple(urls, files):
    async with aiohttp.ClientSession() as session:
        tasks = []
        
        for url in urls:
            tasks.append(scan_url(session, url))
        
        for file_path in files:
            file_hash = get_file_hash(file_path)
            tasks.append(scan_file(session, file_hash))
        
        results = await asyncio.gather(*tasks)
        return results

# Main loop for continuous scanning and user interaction
async def main():
    ascii_art = pyfiglet.figlet_format("Excalibur", font="Slant") 
    print(ascii_art)
    print("Welcome to Excalibur: AI Enhanced Cybersecurity Threat Detector")
    print("Instructions:")
    print("1. Type 'scan_url <url>' to scan a URL.")
    print("2. Type 'scan_file <file_path>' to scan a file.")
    print("3. Type 'exit' to quit the program.")
    print("-------------------------------------------------------------")
    
    # Create a single session for all API calls during the main loop
    async with aiohttp.ClientSession() as session:
        while True:
            command = input("Excalibur> ").strip()

            if command.lower() == "exit":
                print("Exiting the program. Thank you for using Excalibur!")
                break

            elif command.startswith("scan_url "):
                url = command.split(" ", 1)[1]
                result = await scan_url(session, url)
                # Pass the URL string to ai_analysis, not the API response
                prediction = ai_analysis(url)
                print(f"Scan result for {url}:\n{json.dumps(result, indent=2)}")
                print(f"AI Prediction: {prediction}")

            elif command.startswith("scan_file "):
                file_path = command.split(" ", 1)[1]
                if os.path.isfile(file_path):
                    file_hash = get_file_hash(file_path)
                    result = await scan_file(session, file_hash)
                    if result:
                        print(f"Scan result for {file_path}:\n{json.dumps(result, indent=2)}")
                        prediction = ai_file_analysis(result)
                        print(f"AI Prediction: {prediction}")
                else:
                    print(f"File not found: {file_path}")

            else:
                print("Invalid command. Please try again.")

if __name__ == "__main__":
    asyncio.run(main())
