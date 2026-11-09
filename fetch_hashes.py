import json
import requests
import os

API_URL = "https://mb-api.abuse.ch/api/v1/"
AUTH_KEY = os.environ.get("MB_AUTH_KEY")

def get_android_hashes():
    headers = {"Auth-Key": AUTH_KEY} if AUTH_KEY else {}
    threats_dict = {}
    
    # We try all 3 known Android classifications so the file is never empty
    queries = [
        {"query": "get_taginfo", "tag": "Apk", "limit": 200},
        {"query": "get_taginfo", "tag": "android", "limit": 200},
        {"query": "get_file_type", "file_type": "apk", "limit": 200}
    ]
    
    print("Connecting to MalwareBazaar API...")
    
    for payload in queries:
        try:
            resp = requests.post(API_URL, headers=headers, data=payload, timeout=30)
            if resp.status_code == 200:
                result = resp.json()
                
                if result.get("query_status") == "ok":
                    for item in result.get("data", []):
                        hash_val = item.get("sha256_hash")
                        sig = item.get("signature")
                        # Format for Guardian's Room Database
                        name = sig if sig else "Android.Malware.Generic"
                        
                        # Using a dictionary automatically prevents duplicate hashes
                        threats_dict[hash_val] = name 
                        
        except Exception as e:
            print(f"Skipping a payload due to error: {e}")
            
    # Convert the dictionary back into the JSON array format
    return [{"hash": k, "name": v} for k, v in threats_dict.items()]

if __name__ == "__main__":
    try:
        threats = get_android_hashes()
        
        if len(threats) > 0:
            with open("threats.json", "w") as f:
                json.dump(threats, f, indent=2)
            print(f"Success! Saved {len(threats)} unique Android threat hashes.")
        else:
            print("Still receiving no data from API.")
            
    except Exception as e:
        print(f"Critical Script Error: {e}")
