from agents.chatgpt.chrome_cdp_client import ChromeCDPClient
from interactive_js_client import InteractiveJSClient
import logging
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("test_interactive_js.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    """
    Test the interactive JavaScript crawler functionality
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Test interactive JavaScript crawling")
    parser.add_argument("--url", required=True, help="URL to crawl")
    parser.add_argument("--purpose", required=True, help="Purpose of the crawling")
    parser.add_argument("--test-string", help="Test string to verify in results")
    parser.add_argument("--iterations", type=int, default=5, help="Maximum iterations")
    args = parser.parse_args()
    
    try:
        # Initialize Chrome CDP client
        logger.info("Initializing Chrome CDP client")
        chrome_client = ChromeCDPClient()
        
        # Initialize interactive JS client
        logger.info("Initializing Interactive JS client")
        js_client = InteractiveJSClient(chrome_client)
        
        # Run the interactive JavaScript session
        logger.info(f"Starting interactive crawl of {args.url}")
        result = js_client.run_interactive_js_session(
            url=args.url,
            purpose=args.purpose,
            test_string=args.test_string,
            max_iterations=args.iterations
        )
        
        # Display results
        logger.info("=" * 50)
        logger.info(f"Crawl completed with success: {result['success']}")
        
        if result['success']:
            logger.info(f"Iterations: {result['iterations']}")
            logger.info(f"Time taken: {result['time_taken']:.2f} seconds")
            
            if args.test_string:
                logger.info(f"Test string '{args.test_string}' found: {result.get('test_string_found', False)}")
            
            data = result.get('data', [])
            if isinstance(data, list):
                logger.info(f"Extracted {len(data)} data items")
                if data:
                    logger.info("Sample data:")
                    for i, item in enumerate(data[:3]):
                        logger.info(f"  Item {i+1}: {str(item)[:200]}...")
                    if len(data) > 3:
                        logger.info(f"  ... and {len(data) - 3} more items")
            else:
                logger.info(f"Extracted data: {str(data)[:200]}...")
        else:
            logger.error(f"Crawl failed: {result.get('error', 'Unknown error')}")
            
        logger.info("=" * 50)
        return result

    except Exception as e:
        logger.error(f"Error in test script: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None

if __name__ == "__main__":
    main() 