# Conversational JavaScript Crawler

This tool implements a conversational JavaScript execution flow for web crawling using Chrome DevTools Protocol (CDP) and ChatGPT. It enables dynamic analysis of web pages through a back-and-forth conversation between ChatGPT and a browser.

## How It Works

1. **ChatGPT generates JavaScript code** based on the crawling purpose and the HTML content of the page
2. The code is executed in the browser via Chrome DevTools Protocol
3. Results are sent back to ChatGPT
4. ChatGPT analyzes the results and generates the next JavaScript code to continue crawling
5. This process repeats until the crawling is complete

## Features

- Dynamic JavaScript execution in the browser
- Interactive conversation flow between ChatGPT and the browser
- Screenshot and HTML capture for better context
- Detailed logging and error handling
- Support for testing extracted data against a search string
- Complete crawling session history with all steps and results
- Automatic data deduplication

## Setup

1. Ensure you have the `pychrome` library installed:
   ```
   pip install pychrome
   ```

2. Make sure you have a compatible browser installed (Chrome or Brave)

3. Place the following files in your project:
   - `interactive_js_client.py` - The main InteractiveJSClient class
   - `conversational_js_crawler.py` - Command-line interface for the crawler
   - `test_interactive_js.py` - Test script for the crawler

4. Make sure these files can import the `ChromeCDPClient` from the `agents/chatgpt/chrome_cdp_client.py` path

## Usage

Run the conversational JavaScript crawler with the following command:

```bash
python conversational_js_crawler.py --url URL --purpose "Purpose Description" [options]
```

### Command-line Arguments

- `--url`: (Required) The URL to crawl
- `--purpose`: (Required) The purpose of the crawling (what data you want to extract)
- `--test-string`: (Optional) A string to test for in the results
- `--max-iterations`: (Optional, default: 10) Maximum number of conversation iterations
- `--output`: (Optional) Output file path for results (JSON)
- `--browser-profile`: (Optional, default: "Default") Browser profile name

### Example Commands

Extract product information from an e-commerce site:
```bash
python conversational_js_crawler.py --url "https://example-shop.com/products" --purpose "Extract product names, prices, and images" --test-string "price"
```

Extract news articles from a news site:
```bash
python conversational_js_crawler.py --url "https://example-news.com" --purpose "Extract news headlines, dates, and summaries" --max-iterations 5
```

### Output

The crawler will output:
1. A JSON file with the complete session results (stored in `./crawls/` by default)
2. Log files with detailed execution information
3. A summary of the results in the console

## Example Session Result Structure

```json
{
  "url": "https://example.com",
  "purpose": "Extract product information",
  "success": true,
  "iterations": 3,
  "steps": [
    {
      "iteration": 1,
      "js_code": "...",
      "result": {
        "success": true,
        "data": [...],
        "message": "Found product elements"
      },
      "execution_time": 0.5
    },
    ...
  ],
  "data": [
    {"name": "Product 1", "price": "$10.99", "image": "..."},
    {"name": "Product 2", "price": "$24.99", "image": "..."}
  ],
  "test_string_found": true,
  "time_taken": 15.3
}
```

## Troubleshooting

1. **Browser connection issues**: 
   - Make sure the browser is running with remote debugging enabled
   - Check that port 9333 is not already in use

2. **JavaScript execution errors**:
   - Review the logs for detailed JavaScript error messages
   - The crawler will automatically attempt to fix JavaScript errors by sending them back to ChatGPT

3. **ChatGPT response issues**:
   - If ChatGPT is not generating proper JavaScript code, the crawler will retry with a more explicit request

## Advanced Usage

### Custom Browser Configuration

You can modify the browser startup parameters in the `ChromeCDPClient.start_browser` method to customize the browser configuration.

### Integration with Existing Code

You can use the `InteractiveJSClient` class directly in your code:

```python
from agents.chatgpt.chrome_cdp_client import ChromeCDPClient
from interactive_js_client import InteractiveJSClient

# Initialize clients
chrome_client = ChromeCDPClient()
js_client = InteractiveJSClient(chrome_client)

# Run interactive session
result = js_client.run_interactive_js_session(
    url="https://example.com",
    purpose="Extract product information",
    test_string="product",
    max_iterations=5
)

# Process results
print(f"Extracted {len(result['data'])} items")
``` 