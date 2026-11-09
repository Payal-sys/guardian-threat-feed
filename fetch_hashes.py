import json
import requests
import os

API_URL = "https://mb-api.abuse.ch/api/v1/"
AUTH_KEY = os.environ.get("MB_AUTH_KEY")

def debug_android_hashes():
    # Passing both header formats just to be absolutely certain
    headers = {
        "Auth-Key": AUTH_KEY,
        "API-KEY": AUTH_KEY
    } if AUTH_KEY else {}
    
    threats_dict = {}
    
    queries = [
        {"query": "get_taginfo", "tag": "apk", "limit": 200},
        {"query": "get_taginfo", "tag": "android", "limit": 200},
        {"query": "get_file_type", "file_type": "apk", "limit": 200}
    ]
    
    for payload in queries:
        print(f"\n--- Testing Query: {payload['query']} | Param: {list(payload.values())[1]} ---")
        try:
            resp = requests.post(API_URL, headers=headers, data=payload, timeout=30)
            print(f"HTTP Status: {resp.status_code}")
            
            if resp.status_code == 200:
                result = resp.json()
                status = result.get("query_status")
                print(f"API Query Status: {status}")
                
                if status == "ok":
                    data_list = result.get("data", [])
                    print(f"Found {len(data_list)} hashes!")
                    for item in data_list:
                        hash_val = item.get("sha256_hash")
                        sig = item.get("signature")
                        threats_dict[hash_val] = sig if sig else "Android.Malware.Generic"
                else:
                    # This will print the EXACT error message the server is sending
                    print(f"Server Error Data: {result}")
            else:
                print(f"Server HTTP Error: {resp.text}")
                
        except Exception as e:
            print(f"Request failed: {e}")
            
    return [{"hash": k, "name": v} for k, v in threats_dict.items()]

if __name__ == "__main__":
    print("Starting MalwareBazaar API diagnostics...\n")
    threats = debug_android_hashes()
    
    if len(threats) > 0:
        with open("threats.json", "w") as f:
            json.dump(threats, f, indent=2)
        print(f"\nSuccess! Saved {len(threats)} unique Android threat hashes.")
    else:
        print("\nStill receiving no data from API. Please copy and paste this entire terminal log!")
