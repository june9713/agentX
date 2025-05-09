#!/usr/bin/env python
"""
Conversational JavaScript Crawler Demo

This script demonstrates how to use the interactive JavaScript crawler
to extract information from websites through a conversation between
ChatGPT and a browser.

Example usage:
    python demo_js_crawler.py
"""

import os
import sys
import time
import logging
from agents.chatgpt.chrome_cdp_client import ChromeCDPClient
from interactive_js_client import InteractiveJSClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("demo_js_crawler.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def run_demo():
    """Run the conversational JavaScript crawler demo"""
    
    # Sample website and purpose
    demo_url = "https://news.ycombinator.com/"
    demo_purpose = "Extract the top 5 news headlines with their points and comment counts"
    
    print("\n" + "="*70)
    print(f"Conversational JavaScript Crawler Demo")
    print("="*70)
    print(f"Target URL: {demo_url}")
    print(f"Purpose: {demo_purpose}")
    print("="*70 + "\n")
    
    # Initialize Chrome CDP Client
    print("Initializing Chrome CDP client...")
    chrome_client = ChromeCDPClient()
    success = chrome_client.start_browser()
    
    if not success:
        print("Failed to start browser. Please make sure Chrome/Brave is installed.")
        return
    
    print("Browser started successfully")
    
    # Initialize Interactive JavaScript Client
    print("Initializing Interactive JS client...")
    js_client = InteractiveJSClient(chrome_client)
    
    # Run the interactive session
    print(f"\nStarting interactive JavaScript crawling session...")
    print(f"This will involve a conversation between ChatGPT and the browser.")
    print(f"The browser will navigate to {demo_url}")
    print(f"ChatGPT will generate JavaScript code to extract {demo_purpose}")
    print(f"The code will be executed in the browser and results will be sent back to ChatGPT")
    print(f"This process will continue until the crawling is complete\n")
    
    start_time = time.time()
    
    # Get confirmation from user
    input("Press Enter to start the demo...")
    
    try:
        # Run the interactive session with a maximum of 5 iterations
        result = js_client.run_interactive_js_session(
            url=demo_url,
            purpose=demo_purpose,
            max_iterations=5
        )
        
        elapsed_time = time.time() - start_time
        
        # Display results
        print("\n" + "="*70)
        print(f"Crawling {'SUCCESSFUL' if result['success'] else 'FAILED'}")
        print(f"Completed in {elapsed_time:.2f} seconds with {result['iterations']} iterations")
        print("="*70)
        
        # Display extracted data
        if result['success'] and result.get('data'):
            data = result['data']
            print(f"\nExtracted {len(data)} items:")
            
            for i, item in enumerate(data[:10], 1):
                if isinstance(item, dict):
                    # Pretty print dictionary items
                    print(f"\n{i}. {item.get('title', 'No title')}")
                    for key, value in item.items():
                        if key != 'title':
                            print(f"   - {key}: {value}")
                else:
                    # Print non-dictionary items
                    print(f"\n{i}. {item}")
            
            if len(data) > 10:
                print(f"\n... and {len(data) - 10} more items")
        else:
            print(f"\nNo data extracted. Error: {result.get('error', 'Unknown error')}")
        
        # Save results to file
        result_file = "./crawls/demo_result.json"
        os.makedirs(os.path.dirname(result_file), exist_ok=True)
        
        import json
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        print(f"\nFull results saved to: {result_file}")
        print("="*70)
        
        return result
    
    except Exception as e:
        print(f"Error in demo: {e}")
        import traceback
        print(traceback.format_exc())
        return None
    finally:
        print("\nDemo completed. You can examine the logs for more details.")

if __name__ == "__main__":
    run_demo() 