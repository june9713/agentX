import requests
import json
import time
import uuid

def main():
    # Generate unique client ID
    client_id = str(uuid.uuid4())
    print(f"Client ID: {client_id}")
    
    # FastMCP server's SSE endpoint
    sse_url = 'http://127.0.0.1:8000/sse'
    
    try:
        # 1. SSE connection request
        print(f"Attempting SSE connection: {sse_url}")
        # Don't set a long timeout and only get SSE messages
        sse_response = requests.get(
            sse_url, 
            headers={'Accept': 'text/event-stream'},
            stream=True,
            timeout=2  # Short timeout to get only the first event
        )
        
        if sse_response.status_code != 200:
            print(f"SSE connection failed. Status code: {sse_response.status_code}")
            return
            
        print("Receiving SSE response...")
        
        # Extract message URL
        messages_url = None
        for i, line in enumerate(sse_response.iter_lines()):
            if line:
                decoded_line = line.decode('utf-8')
                print(f"Line {i+1}: {decoded_line}")
                
                if "data: /messages/" in decoded_line:
                    messages_path = decoded_line.replace("data: ", "").strip()
                    messages_url = f"http://127.0.0.1:8000{messages_path}"
                    print(f"Message URL: {messages_url}")
                    break
            
            # Safe guard to get URL before timeout
            if i > 5:  # Check only first 5 lines
                break
        
        if not messages_url:
            print("Could not find message URL")
            return
        
        # 2. Try new request to initialize
        init_payload = {
            "jsonrpc": "2.0",
            "id": f"init-{client_id}",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "tools": True,
                    "resources": True,
                    "prompts": True,
                    "completion": True
                },
                "clientInfo": {
                    "name": "python-test-client",
                    "version": "1.0.0"
                }
            }
        }
        
        print("\nSending initialization request...")
        init_response = requests.post(
            messages_url,
            headers={'Content-Type': 'application/json'},
            json=init_payload,
            timeout=5
        )
        
        print(f"Initialization response status: {init_response.status_code}")
        
        # 3. Call tool
        # Wait after initialization
        time.sleep(1)
        
        tool_payload = {
            "jsonrpc": "2.0",
            "id": f"tool-{client_id}",
            "method": "tools/call",
            "params": {
                "name": "chrome_connect",
                "arguments": {
                    "port": 9333,
                    "host": "localhost"
                }
            }
        }
        
        print("\nSending tool call request...")
        tool_response = requests.post(
            messages_url,
            headers={'Content-Type': 'application/json'},
            json=tool_payload,
            timeout=5
        )
        
        print(f"Tool call response status: {tool_response.status_code}")
        
        # Print content
        if tool_response.text:
            try:
                json_response = tool_response.json()
                print(f"JSON response: {json.dumps(json_response, indent=2)}")
            except:
                print(f"Text response: {tool_response.text}")
        
    except requests.exceptions.Timeout:
        print("Timeout occurred - this is normal for SSE connections")
    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    main()