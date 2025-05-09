import logging
import json
import os
import re
import time
import base64
import traceback
import datetime
from urllib.parse import urljoin, urlparse
from js_code_extractor import extract_and_clean_js

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("interactive_js_client.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class InteractiveJSClient:
    """
    Interactive JavaScript execution client for conversational browsing and crawling.
    This class facilitates a conversation between ChatGPT and a browser using Chrome DevTools Protocol,
    where ChatGPT generates JavaScript code that is executed in the browser and results are 
    sent back to ChatGPT.
    """
    
    def __init__(self, chrome_client):
        """
        Initialize the Interactive JS Client.
        
        Args:
            chrome_client: An instance of ChromeCDPClient that handles browser interactions
        """
        self.chrome_client = chrome_client
        self.browser = chrome_client.browser
        self.session_results = []
        
    def run_interactive_js_session(self, url, purpose, test_string=None, max_iterations=10):
        """
        Runs an interactive JavaScript execution session with conversational flow between 
        ChatGPT and the browser.
        
        Args:
            url: The target URL to crawl
            purpose: The purpose of the crawling session
            test_string: Optional string to test for in the results
            max_iterations: Maximum number of conversation iterations
            
        Returns:
            Dictionary containing session results
        """
        crawl_tab = None
        try:
            # Initialize result directories
            tmp_dir = "./tmp/crawl"
            crawls_dir = "./crawls"
            os.makedirs(tmp_dir, exist_ok=True)
            os.makedirs(crawls_dir, exist_ok=True)
            
            # Create filename safe URL and result paths
            current_date = datetime.datetime.now().strftime("%Y%m%d")
            url_filename = re.sub(r'[^\w]', '_', url)
            if len(url_filename) > 50:
                url_filename = url_filename[:50]
            
            result_filename = f"{current_date}_{url_filename}_{purpose[:30]}.json"
            result_path = os.path.join(crawls_dir, result_filename)
            
            logger.info(f"Starting interactive JS session for URL: {url}")
            logger.info(f"Purpose: {purpose}")
            
            # Initialize session results object
            session_result = {
                "url": url,
                "purpose": purpose,
                "success": False,
                "iterations": 0,
                "steps": [],
                "data": None,
                "error": None,
                "test_string_found": False,
                "time_taken": 0
            }
            
            # 1. Create a new browser tab
            logger.info("1. Creating new browser tab")
            crawl_tab = self.browser.new_tab()
            crawl_tab_id = crawl_tab.id
            logger.info(f"Created new tab with ID: {crawl_tab_id}")
            
            crawl_tab.start()
            logger.info("Tab WebSocket connection started")
            
            # Enable network and page domains
            crawl_tab.Network.enable()
            crawl_tab.Page.enable()
            crawl_tab.Runtime.enable()
            self.browser.activate_tab(crawl_tab_id)
            logger.info("Network and Page domains enabled and tab activated")
            
            # 2. Navigate to the target URL
            logger.info(f"2. Navigating to URL: {url}")
            crawl_tab.Page.navigate(url=url)
            
            # Wait for page load
            logger.info("Waiting for page load to complete")
            
            # Use loadEventFired to detect page load
            page_loaded = False
            
            def on_page_load_event(**kwargs):
                nonlocal page_loaded
                page_loaded = True
                logger.info("Page load event fired")
                
            crawl_tab.Page.loadEventFired = on_page_load_event
            
            # Wait with timeout
            load_timeout = 30
            start_time = time.time()
            
            while not page_loaded and time.time() - start_time < load_timeout:
                time.sleep(0.5)
                
            if not page_loaded:
                logger.warning(f"Page load timeout after {load_timeout} seconds")
                
            # Additional wait time for JavaScript execution
            time.sleep(5)
            
            # 3. Capture page state and screenshot
            logger.info("3. Capturing initial page state")
            
            # Get HTML content
            result = crawl_tab.Runtime.evaluate(expression="document.documentElement.outerHTML")
            html_content = result.get('result', {}).get('value', '')
            
            # Save HTML file
            html_filename = os.path.join(tmp_dir, f"{current_date}_{url_filename}_source.html")
            with open(html_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML saved to: {html_filename}")
            
            # Capture screenshot
            screenshot_result = crawl_tab.Page.captureScreenshot()
            screenshot_data = screenshot_result.get('data', '')
            screenshot_filename = None
            
            if screenshot_data:
                screenshot_filename = os.path.join(tmp_dir, f"{current_date}_{url_filename}_screenshot.png")
                with open(screenshot_filename, 'wb') as f:
                    f.write(base64.b64decode(screenshot_data))
                logger.info(f"Screenshot saved to: {screenshot_filename}")
            
            # Get basic page info
            page_info = crawl_tab.Runtime.evaluate(
                expression="""
                (function() {
                    return {
                        title: document.title,
                        url: window.location.href,
                        size: {
                            width: window.innerWidth,
                            height: window.innerHeight
                        },
                        documentReady: document.readyState
                    };
                })()
                """
            )
            page_info = page_info.get('result', {}).get('value', {})
            
            # 4. Start the interactive JS session with ChatGPT
            logger.info("4. Starting interactive JavaScript session with ChatGPT")
            
            # Upload HTML file to ChatGPT
            logger.info(f"Uploading HTML file: {html_filename}")
            self.chrome_client.simulate_paste_local_file(html_filename, self.chrome_client.tab)
            time.sleep(1)
            
            # Upload screenshot if available
            if screenshot_filename and os.path.exists(screenshot_filename):
                logger.info(f"Uploading screenshot: {screenshot_filename}")
                self.chrome_client.simulate_paste_local_file(screenshot_filename, self.chrome_client.tab)
                time.sleep(1)
            
            # Prepare initial prompt for ChatGPT
            initial_prompt = f"""
목적: {purpose}에 관한 웹페이지 크롤링

이 웹페이지({url})를 크롤링하기 위해 JavaScript 코드를 작성해 주세요.
개발자 도구 콘솔에서 바로 실행할 수 있는 JavaScript 코드로 작성해야 합니다.

다음 단계로 진행하겠습니다:
1. 먼저 당신이 첫 번째 JavaScript 코드 조각을 작성해주세요. 이 코드는 페이지를 분석하고 {purpose}와 관련된 데이터를 찾아내는 데 사용됩니다.
2. 나는 그 코드를 브라우저에서 실행하고 결과를 알려드리겠습니다.
3. 그 결과를 바탕으로 후속 작업을 위한 다음 JavaScript 코드를 작성해주세요.
4. 이 과정을 원하는 데이터를 완전히 추출할 때까지 반복하겠습니다.

JavaScript 코드를 작성할 때 다음 가이드라인을 따라주세요:
- 코드는 ```javascript 와 ``` 사이에 작성해야 합니다.
- 코드는 비동기(async/await) 형태로 작성하고 Promise를 사용하여 결과를 반환하세요.
- 코드는 즉시 실행 함수 표현식(IIFE) 형태로 작성하세요. 예: (async function() { ... })()
- JSON 형식으로 결과를 반환하세요.
- 코드가 오류 처리를 포함하도록 해주세요.
- 코드는 한 번에 하나의 작업만 수행하도록 집중하세요.

첫 번째 JavaScript 크롤링 코드를 작성해주세요. 페이지 구조 분석과 크롤링 대상 요소 식별에 집중하세요.
"""

            # Send initial prompt to ChatGPT
            logger.info("Sending initial prompt to ChatGPT")
            self.chrome_client.send_query(self.browser, self.chrome_client.tab, initial_prompt)
            
            # Wait for ChatGPT response
            if not self.chrome_client.wait_for_response_complete(self.chrome_client.tab, timeout=300):
                logger.warning("Initial response waiting timed out")
                session_result["error"] = "Initial response timeout"
                return session_result
            
            # Begin interactive session loop
            start_session_time = time.time()
            iteration = 0
            session_complete = False
            
            while iteration < max_iterations and not session_complete:
                iteration += 1
                logger.info(f"Interactive JS session iteration {iteration}/{max_iterations}")
                session_result["iterations"] = iteration
                
                # Extract JavaScript code from ChatGPT response using the external extractor
                js_code = extract_and_clean_js(self.chrome_client.tab)
                if not js_code:
                    logger.warning("No JavaScript code found in response")
                    
                    # Retry requesting JavaScript code
                    retry_prompt = """
죄송합니다만, 응답에서 JavaScript 코드를 찾을 수 없습니다.
다음 형식으로 JavaScript 코드를 작성해주세요:

```javascript
(async function() {
    try {
        // 페이지 분석 및 데이터 추출 코드
        
        return {
            success: true,
            data: 추출된_데이터,
            message: "분석 결과 메시지"
        };
    } catch (error) {
        return {
            success: false,
            error: error.message,
            message: "오류 발생"
        };
    }
})();
```

코드 블록은 반드시 ```javascript로 시작하고 ```로 끝나야 합니다.
"""
                    self.chrome_client.send_query(self.browser, self.chrome_client.tab, retry_prompt)
                    
                    if not self.chrome_client.wait_for_response_complete(self.chrome_client.tab, timeout=180):
                        logger.warning("Retry response waiting timed out")
                    
                    js_code = extract_and_clean_js(self.chrome_client.tab)
                    if not js_code:
                        logger.error("Failed to get JavaScript code after retry")
                        session_result["error"] = "Failed to extract JavaScript code"
                        break
                
                # Record JS code in step results
                step_result = {
                    "iteration": iteration,
                    "js_code": js_code,
                    "result": None,
                    "execution_time": 0
                }
                
                # Execute JavaScript code in browser tab
                logger.info(f"Executing JavaScript code (iteration {iteration})")
                js_execution_start = time.time()
                
                try:
                    # Execute in browse tab with proper error handling
                    js_result = crawl_tab.Runtime.evaluate(
                        expression=js_code,
                        awaitPromise=True,
                        returnByValue=True,
                        timeout=30000  # 30 second timeout
                    )
                    
                    js_execution_time = time.time() - js_execution_start
                    step_result["execution_time"] = js_execution_time
                    
                    # Check for execution errors
                    js_error = js_result.get('exceptionDetails')
                    if js_error:
                        error_msg = js_error.get('exception', {}).get('description', 'Unknown JS error')
                        error_line = js_error.get('lineNumber', 0)
                        logger.error(f"JavaScript execution error at line {error_line}: {error_msg}")
                        
                        # Create error result object
                        execution_result = {
                            "success": False,
                            "error": error_msg,
                            "errorLine": error_line,
                            "message": "JavaScript execution error"
                        }
                        step_result["result"] = execution_result
                    else:
                        # Process successful execution
                        result_value = js_result.get('result', {}).get('value')
                        logger.info(f"JavaScript execution result: {str(result_value)[:200]}...")
                        
                        # Ensure result is dictionary format
                        if not isinstance(result_value, dict):
                            execution_result = {
                                "success": True,
                                "data": result_value,
                                "message": "JavaScript executed but returned non-standard format"
                            }
                        else:
                            execution_result = result_value
                        
                        step_result["result"] = execution_result
                    
                    # Save step result
                    session_result["steps"].append(step_result)
                    
                    # Check if session is complete
                    if execution_result.get('complete', False) or execution_result.get('message') == "크롤링 완료":
                        logger.info("JavaScript crawling session marked as complete")
                        session_complete = True
                        session_result["success"] = True
                        session_result["message"] = "크롤링이 성공적으로 완료되었습니다."
                        
                        # Extract all data from steps
                        all_data = []
                        for step in session_result["steps"]:
                            if step["result"].get("success", False) and step["result"].get("data"):
                                step_data = step["result"]["data"]
                                if isinstance(step_data, list):
                                    all_data.extend(step_data)
                                elif isinstance(step_data, dict) and "items" in step_data:
                                    all_data.extend(step_data["items"])
                                elif isinstance(step_data, dict):
                                    all_data.append(step_data)
                        
                        # Deduplicate data if possible
                        try:
                            unique_data = []
                            seen_items = set()
                            
                            for item in all_data:
                                item_str = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                                if item_str not in seen_items:
                                    seen_items.add(item_str)
                                    unique_data.append(item)
                            
                            session_result["data"] = unique_data
                        except:
                            session_result["data"] = all_data
                        
                        # Test string checking
                        if test_string:
                            data_str = json.dumps(session_result["data"], ensure_ascii=False)
                            session_result["test_string_found"] = test_string.lower() in data_str.lower()
                            logger.info(f"Test string '{test_string}' found: {session_result['test_string_found']}")
                        
                        break
                    
                    # Prepare next prompt based on results
                    next_prompt = f"""
JavaScript 코드 실행 결과:
```json
{json.dumps(execution_result, ensure_ascii=False, indent=2)}
```

위 결과를 바탕으로 다음 단계의 크롤링을 위한 JavaScript 코드를 작성해주세요.

{f'목표 데이터에 "{test_string}"이 포함되어 있는지 확인해주세요.' if test_string else ''}

아직 목표한 데이터를 완전히 추출하지 못했다면, 다음 작업을 위한 JavaScript 코드를 작성해주세요.
이전 코드의 문제점이 있다면 수정하고, 다음 단계로 진행하세요.

만약 크롤링이 완료되었다면, 최종 결과를 정리하는 JavaScript 코드를 작성하고 결과 객체에 `complete: true`를 포함시켜주세요.

코드는 다음 형식으로 작성해주세요:
```javascript
(async function() {
    try {
        // 이전 결과를 바탕으로 다음 작업 수행
        
        return {
            success: true,
            data: 추출된_데이터,
            message: "작업 상태 메시지"
            // 필요시 complete: true 추가
        };
    } catch (error) {
        return {
            success: false,
            error: error.message,
            message: "오류 발생"
        };
    }
})();
```
"""
                    
                    # Send next prompt to ChatGPT
                    logger.info("Sending next prompt with execution results")
                    self.chrome_client.send_query(self.browser, self.chrome_client.tab, next_prompt)
                    
                    # Wait for ChatGPT response
                    if not self.chrome_client.wait_for_response_complete(self.chrome_client.tab, timeout=300):
                        logger.warning("Next response waiting timed out")
                        break
                
                except Exception as js_exec_error:
                    js_execution_time = time.time() - js_execution_start
                    step_result["execution_time"] = js_execution_time
                    error_msg = str(js_exec_error)
                    
                    logger.error(f"Error during JavaScript execution: {error_msg}")
                    logger.error(traceback.format_exc())
                    
                    # Record error in step result
                    execution_result = {
                        "success": False,
                        "error": error_msg,
                        "message": "JavaScript execution exception"
                    }
                    step_result["result"] = execution_result
                    session_result["steps"].append(step_result)
                    
                    # Send error prompt for next iteration
                    error_prompt = f"""
JavaScript 코드 실행 중 오류가 발생했습니다:
```
{error_msg}
```

이 오류를 해결할 수 있는 새로운 JavaScript 코드를 작성해주세요.
코드는 다음 형식으로 작성해주세요:

```javascript
(async function() {
    try {
        // 오류를 수정한 코드
        
        return {
            success: true,
            data: 추출된_데이터,
            message: "오류 수정 후 실행 결과"
        };
    } catch (error) {
        return {
            success: false,
            error: error.message,
            message: "오류 발생"
        };
    }
})();
```
"""
                    
                    # Send error prompt to ChatGPT
                    logger.info("Sending error prompt for JavaScript fix")
                    self.chrome_client.send_query(self.browser, self.chrome_client.tab, error_prompt)
                    
                    # Wait for ChatGPT response
                    if not self.chrome_client.wait_for_response_complete(self.chrome_client.tab, timeout=180):
                        logger.warning("Error response waiting timed out")
                        break
            
            # Session completion handling
            session_end_time = time.time()
            session_result["time_taken"] = session_end_time - start_session_time
            
            if iteration >= max_iterations and not session_complete:
                logger.warning(f"Maximum iterations ({max_iterations}) reached without completing")
                session_result["success"] = False
                session_result["message"] = f"최대 반복 횟수({max_iterations})에 도달했지만 크롤링이 완료되지 않았습니다."
                
                # Try to collect any available data even if not complete
                all_data = []
                for step in session_result["steps"]:
                    if step["result"].get("success", False) and step["result"].get("data"):
                        step_data = step["result"]["data"]
                        if isinstance(step_data, list):
                            all_data.extend(step_data)
                        elif isinstance(step_data, dict) and "items" in step_data:
                            all_data.extend(step_data["items"])
                        elif isinstance(step_data, dict):
                            all_data.append(step_data)
                
                session_result["data"] = all_data
            
            # Save session results to file
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(session_result, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Session results saved to: {result_path}")
            
            # Cleanup: safely close the browser tab
            if crawl_tab:
                try:
                    logger.info(f"Attempting to safely close tab with ID: {crawl_tab_id}")
                    crawl_tab.stop()
                    self.browser.close_tab(crawl_tab_id)
                    logger.info(f"Tab {crawl_tab_id} safely closed")
                except Exception as tab_close_error:
                    logger.error(f"Error closing tab: {tab_close_error}")
            
            return session_result
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in run_interactive_js_session: {error_msg}")
            logger.error(traceback.format_exc())
            
            # Cleanup: safely close the browser tab on exception
            if crawl_tab:
                try:
                    crawl_tab.stop()
                    self.browser.close_tab(crawl_tab.id)
                except:
                    pass
            
            # Return error session result
            return {
                "url": url,
                "purpose": purpose,
                "success": False,
                "error": error_msg,
                "traceback": traceback.format_exc(),
                "time_taken": 0
            }

# Example usage:
# from agents.chatgpt.chrome_cdp_client import ChromeCDPClient
# chrome_client = ChromeCDPClient()
# js_client = InteractiveJSClient(chrome_client)
# result = js_client.run_interactive_js_session(
#     url="https://example.com",
#     purpose="Extract product information",
#     test_string="product",
#     max_iterations=5
# ) 