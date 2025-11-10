import requests
import time

# Test accessing a share directly
share_id = input("Enter share ID to test: ")
url = f"http://127.0.0.1:5000/s/{share_id}"

print(f"Testing access to {url}")
response = requests.get(url)
print(f"Response status code: {response.status_code}")
print(f"Response content length: {len(response.content)}")

# Wait a moment to see if there are multiple access logs
print("Waiting for logs to be recorded...")
time.sleep(2)
