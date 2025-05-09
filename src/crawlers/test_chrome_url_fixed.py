import requests
import json
import time

def test_get_current_url():
    """Test function that gets the current URL from Chrome using the server running on port 8000"""
    # Server endpoint (running on port 8000)
    # Using the correct JSONRPC format for the FastMCP server
    server_url = "http://localhost:8000/jsonrpc"
    
    # Create payload for JSON-RPC request format
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "chrome_evaluate",
        "params": {
            "expression": "window.location.href",
            "return_by_value": True
        }
    }
    
    try:
        # Send POST request to the server
        headers = {"Content-Type": "application/json"}
        response = requests.post(server_url, json=payload, headers=headers)
        
        # Check if request was successful
        if response.status_code == 200:
            # Parse the response JSON
            result = response.json()
            
            # Extract the result from the JSON-RPC response
            if "result" in result:
                url_result = result["result"]
                print(f"Current Chrome URL: {url_result}")
                return url_result
            elif "error" in result:
                print(f"RPC Error: {result['error']}")
                return None
        else:
            print(f"Error: Server returned status code {response.status_code}")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

if __name__ == "__main__":
    # Test getting the current URL
    print("Fetching current URL from Chrome...")
    url = test_get_current_url()
    
    # If successful, try again after a short delay to demonstrate it works consistently
    if url:
        print("\nWaiting 3 seconds before fetching URL again...")
        time.sleep(3)
        
        print("Fetching URL again...")
        test_get_current_url() 