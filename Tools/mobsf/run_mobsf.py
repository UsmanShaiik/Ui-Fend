import requests
import time
from requests_toolbelt.multipart.encoder import MultipartEncoder
import json

# MobSF API Configuration
API_KEY = 'e3e0d83f87b3ac5c517701a3b26207b4c47bc92c83f3c590384ed2ba715e2ad6'
MOBSF_URL = 'http://localhost:8000/api/v1'

HEADERS = {
    'Authorization': API_KEY,
}

# Upload a file (APK or IPA)
def upload_file(file_path):
    url = f"{MOBSF_URL}/upload"
    
    # Use MultipartEncoder for file upload
    m = MultipartEncoder(
        fields={'file': ('encryptor.apk', open(file_path, 'rb'), 'application/vnd.android.package-archive')}
    )
    
    headers = {
        'Authorization': API_KEY,
        'Content-Type': m.content_type
    }
    
    response = requests.post(url, headers=headers, data=m)
    if response.status_code != 200:
        print(f"Error: {response.status_code}, {response.text}")
    response.raise_for_status()
    return response.json()

def get_json_report(hash):
    url = f"{MOBSF_URL}/report_json"
    headers = {
        'Authorization': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {'hash': hash}
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        print(f"Error: {response.status_code}, {response.text}")
    response.raise_for_status()
    return response.json()


# Get the APK file path from the user
apk_file_path = input("Enter the path to the APK file: ")

# Upload the APK file to MobSF API
upload_response = upload_file(apk_file_path)
hash = upload_response["hash"]

# Get the JSON report from MobSF API
json_report = get_json_report(hash)

# Store the JSON report in a file
file_path = "analysis.json"
with open(file_path, "w") as f:
    json.dump(json_report, f, indent=4)

print(f"JSON report stored in {file_path}")
