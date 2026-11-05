import requests
import json

url = "https://mb-api.abuse.ch/api/v1/"

# Use get_file_type instead of get_taginfo to guarantee we get Android APKs
data = {
    "query": "get_file_type",
    "file_type": "apk",
    "limit": 1000
}

try:
    response = requests.post(url, data=data)
    result = response.json()
    
    threats = []
    status = result.get("query_status")
    
    if status == "ok":
        for entry in result.get("data", []):
            sig = entry.get("signature")
            name = sig if sig else "Android.Malware.Generic"
            threats.append({
                "hash": entry.get("sha256_hash"),
                "name": name
            })
        print(f"Successfully processed {len(threats)} APKs.")
    else:
        # If the API fails, this prints the exact reason why to your GitHub logs
        print(f"API Error! MalwareBazaar returned status: {status}")
            
    # Always write the file, even if empty, so we don't break the Action
    with open("threats.json", "w") as f:
        json.dump(threats, f, indent=2)
        
except Exception as e:
    print(f"Critical Script Error: {e}")
