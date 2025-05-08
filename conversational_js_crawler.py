"""
Conversational JavaScript Crawler - Main Script

This script integrates the Chrome CDP client with our interactive JavaScript client to
provide a conversational JavaScript execution flow for crawling web pages through ChatGPT.

Usage:
    python conversational_js_crawler.py --url URL --purpose "Purpose Description" [--test-string "Test String"]
"""

import os
import sys
import time
import logging
import argparse
import json
import traceback
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("conversational_js_crawler.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    """
    Main function to run the conversational JavaScript crawler
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Run conversational JavaScript crawler")
    parser.add_argument("--url", required=True, help="URL to crawl")
    parser.add_argument("--purpose", required=True, help="Purpose of the crawling")
    parser.add_argument("--test-string", help="Test string to verify in results")
    parser.add_argument("--max-iterations", type=int, default=10, help="Maximum iterations")
    parser.add_argument("--output", help="Output file path (JSON)")
    parser.add_argument("--browser-profile", default="Default", help="Browser profile name")
    args = parser.parse_args()
    
    # Check if interactive_js_client.py exists, if not, print error and exit
    if not os.path.exists("interactive_js_client.py"):
        logger.error("interactive_js_client.py not found! This script requires the InteractiveJSClient.")
        print("Error: interactive_js_client.py not found!")
        print("Please ensure you have created the interactive_js_client.py file.")
        return 1
    
    try:
        # Import required modules
        logger.info("Importing required modules...")
        from agents.chatgpt.chrome_cdp_client import ChromeCDPClient
        from interactive_js_client import InteractiveJSClient
        
        # Set output file path if not provided
        if not args.output:
            # Create safe filename from URL
            import re
            url_filename = re.sub(r'[^\w]', '_', args.url)
            if len(url_filename) > 50:
                url_filename = url_filename[:50]
            
            # Format: YYYYMMDD_URL_PURPOSE.json
            args.output = f"./crawls/{datetime.now().strftime('%Y%m%d')}_{url_filename}_{args.purpose[:30]}.json"
        
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        
        # Initialize ChromeCDPClient
        logger.info(f"Initializing Chrome CDP client with profile '{args.browser_profile}'...")
        chrome_client = ChromeCDPClient()
        success = chrome_client.start_browser(profile_name=args.browser_profile)
        
        if not success:
            logger.error("Failed to start browser")
            print("Error: Failed to start the browser.")
            return 1
        
        # Initialize InteractiveJSClient
        logger.info("Initializing InteractiveJSClient...")
        js_client = InteractiveJSClient(chrome_client)
        
        # Run interactive JavaScript session
        logger.info(f"Starting interactive JavaScript crawling session for: {args.url}")
        logger.info(f"Purpose: {args.purpose}")
        
        start_time = time.time()
        
        result = js_client.run_interactive_js_session(
            url=args.url,
            purpose=args.purpose,
            test_string=args.test_string,
            max_iterations=args.max_iterations
        )
        
        elapsed_time = time.time() - start_time
        logger.info(f"Crawling session completed in {elapsed_time:.2f} seconds")
        
        # Save results
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        logger.info(f"Results saved to: {args.output}")
        
        # Print summary
        print("\n" + "="*50)
        print(f"Crawling {'SUCCESSFUL' if result['success'] else 'FAILED'}")
        print(f"URL: {args.url}")
        print(f"Purpose: {args.purpose}")
        print(f"Iterations: {result.get('iterations', 0)}")
        print(f"Time taken: {elapsed_time:.2f} seconds")
        
        if args.test_string:
            print(f"Test string '{args.test_string}' found: {result.get('test_string_found', False)}")
        
        data = result.get('data', [])
        if isinstance(data, list):
            print(f"Extracted {len(data)} data items")
        else:
            print("Extracted data (non-list format)")
        
        print(f"Results saved to: {args.output}")
        print("="*50)
        
        return 0
    
    except ImportError as ie:
        logger.error(f"Import error: {ie}")
        print(f"Error: Failed to import required modules: {ie}")
        print("Please ensure all required modules are installed.")
        return 1
    
    except Exception as e:
        logger.error(f"Error running conversational JavaScript crawler: {e}")
        logger.error(traceback.format_exc())
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 