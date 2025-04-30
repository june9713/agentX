import requests
import json
import uuid

def get_chrome_url():
    """
    Get the current URL from Chrome using the FastMCP server
    """
    # Server endpoint
    server_url = "http://localhost:8000"
    session_id = str(uuid.uuid4())
    
    # 세션 ID를 쿼리 매개변수로 사용
    message_endpoint = f"{server_url}/messages/?session_id={session_id}"
    
    # Create the JSON-RPC payload
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
        }
        # session_id를 쿼리 매개변수로 전달하므로 여기서는 제거
    }
    
    # Set headers
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        # Send request to server
        print(f"Sending request to: {message_endpoint}")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        response = requests.post(message_endpoint, json=payload, headers=headers)
        
        # Print raw response for debugging
        print(f"Status code: {response.status_code}")
        print(f"Raw response: {response.text}")
        
        # Process response if successful
        if response.status_code == 200:
            result = response.json()
            
            # Check for errors in the response
            if "error" in result:
                print(f"Error: {result['error']}")
                return None
            
            # Extract URL from result
            if "result" in result:
                url = result["result"]
                print(f"Current Chrome URL: {url}")
                return url
            
        return None
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

if __name__ == "__main__":
    print("Fetching current URL from Chrome...")
    url = get_chrome_url() 