import requests
import json
import time
import uuid

def test_get_current_url():
    """Test function that gets the current URL from Chrome using the server running on port 8000"""
    # Server endpoint (running on port 8000)
    server_url = "http://localhost:8000/messages/"
    
    # Create a session ID
    session_id = str(uuid.uuid4())
    
    # Create payload for request
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "callTool",
        "params": {
            "name": "chrome_evaluate",
            "arguments": {
                "expression": "window.location.href",
                "return_by_value": True
            }
        },
        "session_id": session_id
    }
    
    try:
        # Send POST request to the server
        headers = {"Content-Type": "application/json"}
        response = requests.post(server_url, json=payload, headers=headers)
        
        # Check if request was successful
        if response.status_code == 200:
            # Parse the response JSON
            result = response.json()
            print(f"Full response: {json.dumps(result, indent=2)}")
            
            # Extract the result
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

def test_list_tools():
    """Test function to list all available tools"""
    server_url = "http://localhost:8000/messages/"
    
    # Create a session ID
    session_id = str(uuid.uuid4())
    
    # Create payload for request
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "listTools",
        "params": {},
        "session_id": session_id
    }
    
    try:
        # Send POST request to the server
        headers = {"Content-Type": "application/json"}
        response = requests.post(server_url, json=payload, headers=headers)
        
        # Check if request was successful
        if response.status_code == 200:
            # Parse the response JSON
            result = response.json()
            print(f"Available tools: {json.dumps(result, indent=2)}")
            return result
        else:
            print(f"Error: Server returned status code {response.status_code}")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

if __name__ == "__main__":
    # Test listing tools first to understand what's available
    print("Listing available tools...")
    tools = test_list_tools()
    
    if tools:
        print("\nFetching current URL from Chrome...")
        url = test_get_current_url()
        
        # If successful, try again after a short delay
        if url:
            print("\nWaiting 3 seconds before fetching URL again...")
            time.sleep(3)
            
            print("Fetching URL again...")
            test_get_current_url() 