import win32ui
import win32gui
import win32con
import numpy as np
import cv2
import time
import pyautogui
import os
import subprocess
import win32api
import pychrome
import psutil
import traceback
import base64
import logging
# extract cmd field from JSON
import json
import re
from cmdman.cmd_manager import *
import websocket
import threading
import inspect

# logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("myagent.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

print("chatgpt.py file loading completed", PersistentCmdManager)

class ChromeCDPClient:
    """
    Chrome DevTools Protocol client class
    Class for interacting with ChatGPT and controlling the browser
    """
    
    def __init__(self , browser_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe" , profile_name = "Default" , position = (0, 0) , size = (1024, 768) , pythonpath = "./Scripts/python.exe"):
        """
        Initialize ChromeCDPClient class
        """
        self.browser_path = browser_path
        self.brower_exe = os.path.basename(browser_path)
        self.profile_name = profile_name
        self.position = position
        self.pythonpath = pythonpath
        self.size = size
        self.browser = None
        self.tab = None
        self.tab2 = None
        
        
        # debug logging setup
        self.setup_debug_logging()
        
        self.start_browser()
        
    def setup_debug_logging(self):
        """
        Set up additional logging for WebSocket debugging
        """
        
    def capture_window(self, hwnd):
        """
        Capture a screenshot from a window handle.
        Performance optimized version
        """
        try:
            # get window size info from window handle
            left, top, right, bottom = win32gui.GetWindowRect(hwnd)
            width = right - left
            height = bottom - top
            
            # if window size is too large, reduce it (memory usage optimization)
            scale_factor = 1.0
            max_dimension = 1920  # maximum dimension limit
            
            if width > max_dimension or height > max_dimension:
                scale_factor = min(max_dimension / width, max_dimension / height)
                target_width = int(width * scale_factor)
                target_height = int(height * scale_factor)
            else:
                target_width = width
                target_height = height

            # create window DC
            window_dc = win32gui.GetWindowDC(hwnd)
            dc_obj = win32ui.CreateDCFromHandle(window_dc)
            compatible_dc = dc_obj.CreateCompatibleDC()

            # create bitmap
            dataBitMap = win32ui.CreateBitmap()
            dataBitMap.CreateCompatibleBitmap(dc_obj, width, height)
            compatible_dc.SelectObject(dataBitMap)

            # capture screen using BitBlt
            compatible_dc.BitBlt((0, 0), (width, height), dc_obj, (0, 0), win32con.SRCCOPY)

            # convert bitmap info to numpy array
            signedIntsArray = dataBitMap.GetBitmapBits(True)
            img = np.frombuffer(signedIntsArray, dtype='uint8')
            img.shape = (height, width, 4)

            # convert to CV2 image in BGR format
            img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
            
            # if needed, resize image (memory and processing time optimization)
            if scale_factor < 1.0:
                img = cv2.resize(img, (target_width, target_height), interpolation=cv2.INTER_AREA)

            # release memory
            dc_obj.DeleteDC()
            compatible_dc.DeleteDC()
            win32gui.ReleaseDC(hwnd, window_dc)
            win32gui.DeleteObject(dataBitMap.GetHandle())

            return img
        except Exception as e:
            logger.error(f"Error capturing window: {e}")
            logger.error(traceback.format_exc())
            return None

    def bring_to_foreground(self, hwnd):
        """
        Bring window to foreground
        """
        try:
            # check if current window is minimized
            if win32gui.IsIconic(hwnd):
                # if minimized, restore
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            
            # prevent focus change problem by simulating Alt key
            pyautogui.keyDown('alt')
            pyautogui.keyUp('alt')
            
            # bring window to top
            win32gui.SetForegroundWindow(hwnd)
            win32gui.BringWindowToTop(hwnd)
            win32gui.SetActiveWindow(hwnd)
            
            return True
        except Exception as e:
            logger.error(f"Error bringing window to foreground: {e}")
            return False

    def resize_window(self, hwnd, width, height, x=None, y=None):
        """
        Change window size
        """
        try:
            # get current window position and size info
            left, top, right, bottom = win32gui.GetWindowRect(hwnd)
            
            # if x, y is not specified, use current position
            if x is None:
                x = left
            if y is None:
                y = top
            
            # move window and resize
            win32gui.SetWindowPos(
                hwnd,
                win32con.HWND_TOP,
                x,
                y,
                width,
                height,
                win32con.SWP_SHOWWINDOW
            )
            return True
        except Exception as e:
            logger.error(f"Error resizing window: {e}")
            return False

        
    def analisys_crawl_page(self, browser, url, purpose, test_string):
        """
        Analyze crawling page and extract necessary information.
        Create a new tab, navigate to the URL, check HTML source,
        analyze each element and JS source to identify the appropriate Crawling method for the purpose.
        If online JS/CSS sources need to be downloaded, use the requests module.
        Downloaded source files are saved in ./tmp/crawl
        After identifying the Crawling method, organize the results into a file
        and save in ./crawls folder with {date}{url with special chars removed}{purpose} filename.
        
        The sequence is as follows:
        1. Create new tab
        2. Navigate to webpage
        3. When page load completes, save HTML file to tmp/crawl folder
        4. Send file to ChatGPT to identify Crawling method
        5. ChatGPT downloads additional source files from online if needed
        6. ChatGPT identifies Crawling method and organizes results for future web automation
        saves to ./crawls folder as {date}{url with special chars removed}{purpose} file
        7. If needed, perform various repeated analyses until desired results are achieved
        """
        try:
            import os
            import re
            import time
            import datetime
            import requests
            import json
            from urllib.parse import urljoin, urlparse
            
            # create necessary directories
            tmp_dir = "./tmp/crawl"
            crawls_dir = "./crawls"
            os.makedirs(tmp_dir, exist_ok=True)
            os.makedirs(crawls_dir, exist_ok=True)
            
            # get current date
            current_date = datetime.datetime.now().strftime("%Y%m%d")
            
            # create filename from URL by removing special characters
            url_filename = re.sub(r'[^\w]', '_', url)
            if len(url_filename) > 50:  # file name length limit
                url_filename = url_filename[:50]
            
            # create result file path
            result_filename = f"{current_date}_{url_filename}_{purpose}.json"
            result_path = os.path.join(crawls_dir, result_filename)
            
            logger.info(f"Starting crawl analysis for URL: {url}")
            logger.info(f"Purpose: {purpose}")
            
            # 1. create new tab
            logger.info("1. Creating new tab")
            crawl_tab = browser.new_tab()
            crawl_tab_id = crawl_tab.id  # needed later to close tab
            logger.info(f"Created new tab with ID: {crawl_tab_id}")
            
            crawl_tab.start()
            logger.info("Tab WebSocket connection started")
            
            # enable network and page domains
            crawl_tab.Network.enable()
            crawl_tab.Page.enable()
            crawl_tab.Runtime.enable()  # enable JavaScript execution
            browser.activate_tab(crawl_tab_id)
            logger.info("Network and Page domains enabled and tab activated")
            
            # 2. navigate to URL
            logger.info(f"2. Navigating to URL: {url}")
            crawl_tab.Page.navigate(url=url)
            
            # wait for page load to complete
            logger.info("Waiting for page load to complete")
            
            # wait for DOM completion event
            page_loaded = False
            
            def on_page_load_event(**kwargs):
                nonlocal page_loaded
                page_loaded = True
                logger.info("Page load event fired")
                
            # register event listener
            crawl_tab.Page.loadEventFired = on_page_load_event
            
            # set timeout
            load_timeout = 30
            start_time = time.time()
            
            # wait for page load
            while not page_loaded and time.time() - start_time < load_timeout:
                time.sleep(0.5)
                
            if not page_loaded:
                logger.warning(f"Page load timeout after {load_timeout} seconds")
                
            # additional time waiting (for JavaScript execution to complete)
            time.sleep(5)
            
            # 3. when page load completes, save HTML file to tmp/crawl folder
            logger.info("3. Saving HTML content")
            
            # get current HTML content
            result = crawl_tab.Runtime.evaluate(expression="document.documentElement.outerHTML")
            html_content = result.get('result', {}).get('value', '')
            
            # save HTML file
            html_filename = os.path.join(tmp_dir, f"{current_date}_{url_filename}_source.html")
            with open(html_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML saved to: {html_filename}")
            
            # analyze DOM structure and rendered state
            logger.info("Analyzing DOM structure and rendered state")
            
            # capture full page screenshot
            screenshot_result = crawl_tab.Page.captureScreenshot()
            screenshot_data = screenshot_result.get('data', '')
            if screenshot_data:
                screenshot_filename = os.path.join(tmp_dir, f"{current_date}_{url_filename}_screenshot.png")
                with open(screenshot_filename, 'wb') as f:
                    f.write(base64.b64decode(screenshot_data))
                logger.info(f"Screenshot saved to: {screenshot_filename}")
            
            # collect basic page info
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
            
            # 4. starting interactive JavaScript crawling session with ChatGPT
            logger.info("4. Starting interactive JavaScript crawling session with ChatGPT")
            
            # first upload HTML file to ChatGPT
            logger.info(f"Uploading HTML file: {html_filename}")
            self.simulate_paste_local_file(html_filename, self.tab)
            time.sleep(1)  # wait for upload to complete
            
            # also upload screenshot
            if os.path.exists(screenshot_filename):
                logger.info(f"Uploading screenshot: {screenshot_filename}")
                self.simulate_paste_local_file(screenshot_filename, self.tab)
                time.sleep(1)
            
            # initialize interactive crawling session
            max_iterations = 10  # maximum number of iterations
            iteration = 0
            final_result = {"steps": []}
            crawling_complete = False
            
            # write initial prompt - request JavaScript crawling code
            initial_prompt = f"""
Purpose: Crawl the webpage for {purpose}

Write JavaScript code to crawl this webpage ({url}).
The code must be executable directly in the developer tools console.

Next steps:
1. First, write the first JavaScript code snippet. This code will be used to analyze the page and find data related to {purpose}.
2. I will run the code in the browser and tell you the result.
3. Based on the result, write the next JavaScript code for the subsequent work.
4. Repeat this process until you have extracted the desired data completely.

When writing JavaScript code, follow these guidelines:
- The code must be written between ```javascript and ```.
- The code must be written in async/await form and return the result using Promise.
- The code must be written in IIFE (Immediately Invoked Function Expression) form. For example: (async function() { ... })()
- Return the result in JSON format.
- The code must include error handling.
- The code must focus on performing one task at a time.

Write the first JavaScript crawling code. Focus on analyzing the page structure and identifying the target elements for crawling.
"""

            logger.info("Sending initial prompt to ChatGPT")
            self.send_query(browser, self.tab, initial_prompt)
            
            # wait for response
            if not self.wait_for_response_complete(self.tab, timeout=300):
                logger.warning("Initial response waiting timed out")
                return "Error: ChatGPT response waiting timed out"
            
            # repeat crawling session
            while iteration < max_iterations and not crawling_complete:
                iteration += 1
                logger.info(f"JavaScript crawling iteration {iteration}/{max_iterations}")
                
                # extract JavaScript code from ChatGPT response
                js_code = self.extract_javascript_code(self.tab)
                if not js_code:
                    logger.warning("No JavaScript code found in response")
                    
                    # retry JavaScript code request
                    retry_prompt = """
I'm sorry, but I couldn't find any JavaScript code in the response.
Please write the JavaScript code in the following format:

```javascript
(async function() {
    try {
        // code for analyzing the page and extracting data
        
        return {
            success: true,
            data: extracted_data,
            message: "analysis result message"
        };
    } catch (error) {
        return {
            success: false,
            error: error.message,
            message: "error occurred"
        };
    }
})();
```

The code block must start with ```javascript and end with ```.
"""
                    self.send_query(browser, self.tab, retry_prompt)
                    
                    if not self.wait_for_response_complete(self.tab, timeout=180):
                        logger.warning("Retry response waiting timed out")
                    
                    js_code = self.extract_javascript_code(self.tab)
                    if not js_code:
                        logger.error("Failed to get JavaScript code after retry")
                        break
                
                # execute JavaScript code
                logger.info(f"Executing JavaScript code (iteration {iteration})")
                try:
                    # execute JavaScript code in crawl tab
                    js_result = crawl_tab.Runtime.evaluate(
                        expression=js_code,
                        awaitPromise=True,
                        returnByValue=True,
                        timeout=30000  # 30 seconds timeout
                    )
                    
                    # check execution result
                    js_error = js_result.get('exceptionDetails')
                    if js_error:
                        error_msg = js_error.get('exception', {}).get('description', 'Unknown JS error')
                        logger.error(f"JavaScript execution error: {error_msg}")
                        
                        # create result object with error information
                        execution_result = {
                            "success": False,
                            "error": error_msg,
                            "message": "error occurred during JavaScript execution"
                        }
                    else:
                        # if execution is successful, extract the result
                        result_value = js_result.get('result', {}).get('value')
                        logger.info(f"JavaScript execution result: {str(result_value)[:200]}...")
                        
                        # if the result is not a dictionary, convert it to a dictionary
                        if not isinstance(result_value, dict):
                            execution_result = {
                                "success": True,
                                "data": result_value,
                                "message": "JavaScript was executed, but the expected format was not found."
                            }
                        else:
                            execution_result = result_value
                    
                    # save step result
                    step_result = {
                        "iteration": iteration,
                        "js_code": js_code,
                        "result": execution_result
                    }
                    final_result["steps"].append(step_result)
                    
                    # check if crawling is complete - check various completion signals
                    is_complete = False
                    
                    # 1. check complete flag
                    if execution_result.get('complete', False):
                        logger.info("Crawling process marked as complete via 'complete' flag")
                        is_complete = True
                        
                    # 2. check message content
                    if not is_complete:
                        complete_messages = ["crawling complete", "crawl complete", "extraction complete", "completed"]
                        msg = str(execution_result.get('message', '')).lower()
                        for complete_msg in complete_messages:
                            if complete_msg.lower() in msg:
                                logger.info(f"Crawling process marked as complete via message: '{msg}'")
                                is_complete = True
                                break
                    
                    # 3. check data (if the desired data is included)
                    if not is_complete and test_string and execution_result.get('success', False):
                        data_str = json.dumps(execution_result.get('data', {}), ensure_ascii=False).lower()
                        if test_string.lower() in data_str:
                            logger.info(f"Crawling process potentially complete - test string '{test_string}' found in data")
                            # additional check: if there is no message or flag, consider it as explicit data completion
                            if isinstance(execution_result.get('data', {}), dict) and len(execution_result.get('data', {})) > 0:
                                logger.info("Data is complete dictionary, marking as complete")
                                is_complete = True
                    
                    if is_complete:
                        logger.info("Crawling process marked as complete")
                        crawling_complete = True
                        final_result["success"] = True
                        final_result["message"] = "crawling  was successful"
                        break
                        
                    # next JavaScript code request prompt
                    next_prompt = f"""
JavaScript code execution result:
```json
{json.dumps(execution_result, ensure_ascii=False, indent=2)}
```

Based on the above result, please write the next JavaScript code for the subsequent crawling.

{f'Please check if the target data contains "{test_string}"' if test_string else ''}

If you have not yet completely extracted the target data, please write the next JavaScript code for the subsequent crawling.
If there is a problem with the previous code, fix it and proceed to the next step.

If the crawling is complete, please write the JavaScript code to summarize the final result and include `complete: true` in the result object.

The code must be written in the following format:
```
(async function() {{
    try {{
        // perform the next task based on the previous result
        
        return {{
            success: true,
            data: extracted_data,
            message: "task status message"
            // if necessary, add complete: true
        }};
    }} catch (error) {{
        return {{
            success: false,
            error: error.message,
            message: "error occurred"
        }};
    }}
}})();
```
"""
                    
                    #send next prompt
                    logger.info("Sending next prompt with execution results")
                    self.send_query(browser, self.tab, next_prompt)
                    
                    if not self.wait_for_response_complete(self.tab, timeout=300):
                        logger.warning("Next response waiting timed out")
                        break
                
                except Exception as js_exec_error:
                    logger.error(f"Error during JavaScript execution: {js_exec_error}")
                    
                    # error information prompt
                    error_prompt = f"""
JavaScript code execution error occurred:
```
{str(js_exec_error)}
```

Please write a new JavaScript code that can fix this error.
The code must be written in the following format:

```
(async function() {{
    try {{
        // code to fix the error
        
        return {{
            success: true,
            data: extracted_data,
            message: "result after fixing the error"
        }};
    }} catch (error) {{
        return {{
            success: false,
            error: error.message,
            message: "error occurred"
        }};
    }}
}})();
```
"""
                    
                    # send error prompt
                    logger.info("Sending error prompt for JavaScript fix")
                    self.send_query(browser, self.tab, error_prompt)
                    
                    if not self.wait_for_response_complete(self.tab, timeout=180):
                        logger.warning("Error response waiting timed out")
                        break
            
            # final result summary
            if iteration >= max_iterations and not crawling_complete:
                logger.warning(f"Maximum iterations ({max_iterations}) reached without completing crawling")
                final_result["success"] = False
                final_result["message"] = f"Maximum iterations ({max_iterations}) reached without completing crawling"
            
            # extract crawled data
            crawled_data = []
            for step in final_result["steps"]:
                if step["result"].get("success", False) and step["result"].get("data"):
                    data = step["result"]["data"]
                    if isinstance(data, list):
                        crawled_data.extend(data)
                    elif isinstance(data, dict) and "items" in data:
                        crawled_data.extend(data["items"])
                    elif isinstance(data, dict):
                        crawled_data.append(data)
            
            # remove duplicates (if possible)
            try:
                unique_data = []
                seen_items = set()
                
                for item in crawled_data:
                    item_str = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                    if item_str not in seen_items:
                        seen_items.add(item_str)
                        unique_data.append(item)
                
                final_result["data"] = unique_data
            except:
                final_result["data"] = crawled_data
            
            # check test_string
            if test_string:
                data_str = json.dumps(final_result["data"], ensure_ascii=False)
                final_result["test_string_found"] = test_string.lower() in data_str.lower()
                logger.info(f"Test string '{test_string}' found: {final_result['test_string_found']}")
            
            # save result file
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(final_result, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Final crawling result saved to: {result_path}")
            
            # safely close tab
            try:
                logger.info(f"Attempting to safely close tab with ID: {crawl_tab_id}")
                self.complete_tab_cleanup(browser, crawl_tab)
            except Exception as e:
                logger.error(f"Error during tab cleanup: {e}")
                logger.error(traceback.format_exc())
                # clean up variables
                crawl_tab = None
            
            # return result object
            result_obj = {
                'success': final_result["success"],
                'result_file': result_path,
                'html_file': html_filename,
                'iterations': iteration,
                'crawling_complete': crawling_complete,
                'data': final_result["data"],
                'message': final_result["message"] if "message" in final_result else ""
            }
            
            return result_obj
            
        except Exception as e:
            logger.error(f"Error in analisys_crawl_page: {e}")
            logger.error(traceback.format_exc())
            
            # even if an error occurs, try to create a crawling result file
            try:
                error_result = {
                    'error': str(e),
                    'target_url': url,
                    'purpose': purpose,
                    'date': datetime.datetime.now().strftime("%Y%m%d"),
                    'traceback': traceback.format_exc()
                }
                
                with open(result_path, 'w', encoding='utf-8') as f:
                    json.dump(error_result, f, ensure_ascii=False, indent=2)
                
                logger.info(f"Error information saved to: {result_path}")
            except:
                pass
                
            return {
                'success': False,
                'error': str(e)
            }

    
    def extract_javascript_code(self, tab):
        """
        Extract JavaScript code from ChatGPT response
        """
        try:
            js_code = """
            (function() {
                try {
                    // find JavaScript code block
                    const jsBlocks = [];
                    
                    // find code block (```javascript ... ``` format)
                    const codeElements = document.querySelectorAll('pre code.language-javascript');
                    if (codeElements.length > 0) {
                        // use the last JavaScript code block
                        return codeElements[codeElements.length - 1].textContent;
                    }
                    
                    // check general code block
                    const preElements = document.querySelectorAll('pre');
                    for (const pre of preElements) {
                        // check the text inside the pre element
                        const text = pre.textContent || '';
                        if (text.includes('async function') || 
                            text.includes('function(') || 
                            text.includes('return {') ||
                            text.includes('document.querySelector')) {
                            jsBlocks.push(text);
                        }
                    }
                    
                    // if there is a JavaScript code block, return the last one
                    if (jsBlocks.length > 0) {
                        return jsBlocks[jsBlocks.length - 1];
                    }
                    
                    // find code block in Markdown text
                    const markdownElements = document.querySelectorAll('.markdown');
                    if (markdownElements.length > 0) {
                        const lastMarkdown = markdownElements[markdownElements.length - 1];
                        const text = lastMarkdown.textContent || '';
                        
                        // find ```javascript ... ``` pattern
                        const jsRegex = /```(?:javascript|js)([\\s\\S]*?)```/g;
                        const matches = [];
                        let match;
                        
                        while ((match = jsRegex.exec(text)) !== null) {
                            matches.push(match[1].trim());
                        }
                        
                        if (matches.length > 0) {
                            return matches[matches.length - 1];
                        }
                        
                        // find general code block
                        const codeRegex = /```([\\s\\S]*?)```/g;
                        const codeMatches = [];
                        
                        while ((match = codeRegex.exec(text)) !== null) {
                            const code = match[1].trim();
                            if (code.includes('async function') || 
                                code.includes('function(') || 
                                code.includes('return {') ||
                                code.includes('document.querySelector')) {
                                codeMatches.push(code);
                            }
                        }
                        
                        if (codeMatches.length > 0) {
                            return codeMatches[codeMatches.length - 1];
                        }
                    }
                    
                    return '';
                } catch (error) {
                    console.error('Error extracting JavaScript code:', error);
                    return '';
                }
            })();
            """
            
            result = tab.Runtime.evaluate(expression=js_code)
            code = result.get('result', {}).get('value', "")
            
            if code:
                # check JavaScript code validity
                if code.startswith('```javascript') and code.endswith('```'):
                    code = code[13:-3].strip()  # remove ```javascript and ```
                elif code.startswith('```js') and code.endswith('```'):
                    code = code[5:-3].strip()  # remove ```js and ```
                elif code.startswith('```') and code.endswith('```'):
                    code = code[3:-3].strip()  # remove ``` and ```
                
                logger.info(f"Found JavaScript code ({len(code)} characters)")
                return code
            else:
                logger.warning("No JavaScript code found")
                return ""
            
        except Exception as e:
            logger.error(f"Error extracting JavaScript code: {e}")
            return ""

    def start_browser(self, profile_name="Default", position=(0, 0), size=(1024, 768)):
        """
        Start Brave browser and connect to debugging port.
        Apply performance-optimized options
        """
        try:
            # kill running Brave browser
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == self.brower_exe:
                    logger.info("Closing existing Brave browser...")
                    try:
                        proc.kill()
                    except Exception as e:
                        logger.warning(f"Failed to kill process: {e}")
            
            time.sleep(1)  # 대기 시간 감소 (2초 → 1초)
            
            # check screen resolution
            screen_width, screen_height = pyautogui.size()
            
            # use default position and size, adjust if out of screen range
            x, y = position
            width, height = size
            
            if x + width > screen_width:
                x = max(0, screen_width - width)
            if y + height > screen_height:
                y = max(0, screen_height - height)
            
            # browser start command - add performance-optimized options
            cmd = self.browser_path + ' ' \
                f'--remote-debugging-port=9333 ' \
                f'--window-size={width},{height} ' \
                f'--window-position={x},{y} ' \
                f'--profile-directory="{profile_name}" ' \
                f'--disable-extensions ' \
                f'--disable-gpu ' \
                f'--no-sandbox ' \
                f'--disable-dev-shm-usage ' \
                f'--disable-software-rasterizer'
            
            logger.info(f"Starting browser with command: {cmd}")
            ps = subprocess.Popen(cmd)
            
            cmd2 = self.browser_path + ' ' \
                f'--remote-debugging-port=9444' \
                f'--window-size={width},{height} ' \
                f'--window-position={x},{y} ' \
                f'--profile-directory="{profile_name}" ' \
                f'--disable-extensions ' \
                f'--disable-gpu ' \
                f'--no-sandbox ' \
                f'--disable-dev-shm-usage ' \
                f'--disable-software-rasterizer'
            
            logger.info(f"Starting browser with command: {cmd}")
            #ps2 = subprocess.Popen(cmd2)
            
            # wait for browser to start and debugging port to be ready
            max_attempts = 10
            attempts = 0
            self.browser = None
            self.tab = None
            self.tab2 = None
            
            # clean up previous created tabs
            try:
                # if previous browser instance exists, clean up tabs
                if self.browser:
                    logger.info("Cleaning up previous browser tabs")
                    tabs = self.browser.list_tab()
                    for tab in tabs:
                        try:
                            tab_id = tab.get('id')
                            if tab_id:
                                logger.info(f"Closing previous tab: {tab_id}")
                                self.browser.close_tab(tab_id)
                        except Exception as e:
                            logger.warning(f"Error closing previous tab: {e}")
            except Exception as e:
                logger.warning(f"Error during previous tabs cleanup: {e}")
                
            while attempts < max_attempts:
                try:
                    time.sleep(0.5)  # decrease waiting time (1 second → 0.5 second)
                    self.browser = pychrome.Browser(url="http://127.0.0.1:9333")
                    logger.info("Connected to Chrome DevTools Protocol")
                    break
                except Exception as e:
                    logger.warning(f"Browser not ready yet, retrying... ({attempts+1}/{max_attempts})")
                    attempts += 1
                    if attempts >= max_attempts:
                        logger.error(f"Failed to connect to browser: {e}")
                        return False
                
                # check all open tabs
                try:
                    existing_tabs = self.browser.list_tab()
                    logger.info(f"Found {len(existing_tabs)} existing tabs")
                    
                    # if there is an existing tab, close all
                    for tab in existing_tabs:
                        try:
                            tab_id = tab.get('id')
                            if tab_id:
                                logger.info(f"Closing existing tab: {tab_id}")
                                self.browser.close_tab(tab_id)
                        except Exception as e:
                            logger.warning(f"Error closing existing tab: {e}")
                except Exception as e:
                    logger.warning(f"Error listing or closing existing tabs: {e}")
                
                # create new tab
                attempts = 0
            while attempts < max_attempts:
                try:
                    time.sleep(0.5)  # decrease waiting time (1 second → 0.5 second)
                    self.tab = self.browser.new_tab()
                    logger.info(f"Created main tab with ID: {self.tab.id}")
                    self.tab.start()
                    logger.info("Started main tab WebSocket connection")
                    break
                except Exception as e:
                    logger.warning(f"tab1 not ready yet, retrying... ({attempts+1}/{max_attempts})")
                    attempts += 1
                    if attempts >= max_attempts:
                        logger.error(f"Failed to connect to browser: {e}")
                        return False
            
                attempts = 0
            while attempts < max_attempts:
                try:
                    time.sleep(0.5)  # decrease waiting time (1 second → 0.5 second)
                    self.tab2 = self.browser.new_tab()
                    logger.info(f"Created secondary tab with ID: {self.tab2.id}")
                    self.tab2.start()
                    logger.info("Started secondary tab WebSocket connection")
                    break
                except Exception as e:
                    logger.warning(f"tab2 not ready yet, retrying... ({attempts+1}/{max_attempts})")
                    attempts += 1
                    if attempts >= max_attempts:
                        logger.error(f"Failed to connect to tab2: {e}")
                        return False
            
                # enable network and navigate to page
            try:
                self.tab.Network.enable()
                self.tab2.Network.enable()
                logger.info("Enabled Network domain for both tabs")
            
                # navigate to ChatGPT page
                url = "https://chatgpt.com/?model=gpt-4o-mini&temporary-chat=false"
                logger.info(f"Navigating to {url}")
                self.tab.Page.navigate(url=url, _timeout=5)  # decrease timeout (10 seconds → 5 seconds)
                # wait for page loading
                self.tab.wait(5)  # decrease waiting time (10 seconds → 5 seconds)
            
                if self.tab2:
                    url = "https://chatgpt.com/?model=gpt-4o-mini&temporary-chat=false"
                    logger.info(f"Navigating secondary tab to {url}")
                    self.tab2.Page.navigate(url=url, _timeout=5)  # decrease timeout (10 seconds → 5 seconds)
                    self.tab2.wait(5)  # decrease waiting time (10 seconds → 5 seconds)
            except Exception as e:
                logger.error(f"Error during tab initialization: {e}")
                logger.error(traceback.format_exc())
            
     
            return True
        
        except Exception as e:
            logger.error(f"Error starting browser: {e}")
            logger.error(traceback.format_exc())
            return False

    def check_page_loaded(self, tab, timeout=15):  # decrease timeout (30 seconds → 15 seconds)
        """
        Check if the page is fully loaded.
        Apply more efficient loading check method
        """
        try:
            start_time = time.time()
            polling_interval = 0.3  # initial polling interval 0.3 seconds
            
            while time.time() - start_time < timeout:
                # check page load status - use more efficient selector
                js_code = '''
                    (function() {
                        if (document.readyState !== 'complete') return 0;
                        const textarea = document.querySelector('#prompt-textarea');
                        return textarea ? 1 : 0;
                    })()
                '''
                result = tab.Runtime.evaluate(expression=js_code)
                
                if result.get('result', {}).get('value', 0) == 1:
                    logger.info("Page fully loaded")
                    return True
                
                # apply dynamic polling interval (increase interval over time)
                elapsed = time.time() - start_time
                polling_interval = min(1.0, 0.3 + (elapsed / 10))  # maximum 1 second
                time.sleep(polling_interval)
            
            logger.warning("Timeout waiting for page to load")
            return False
        
        except Exception as e:
            logger.error(f"Error checking page load: {e}")
            return False

    def simulate_paste_local_file(self, filename, tab):
        """
        Simulate pasting a local file into the browser.
        """
        try:
            full_path = os.path.abspath(filename)
            if not os.path.exists(full_path):
                logger.error(f"File not found: {full_path}")
                return False
                
            # read file
            with open(full_path, "rb") as f:
                image_data = f.read()
            
            # encode to Base64
            image_base64 = base64.b64encode(image_data).decode('utf-8')
            
            # determine file type
            file_ext = os.path.splitext(filename)[1].lower()
            mime_type = 'image/png'  # default value
            
            if file_ext == '.jpg' or file_ext == '.jpeg':
                mime_type = 'image/jpeg'
            elif file_ext == '.png':
                mime_type = 'image/png'
            elif file_ext == '.pdf':
                mime_type = 'application/pdf'
            elif file_ext == '.txt':
                mime_type = 'text/plain'
            elif file_ext == '.js':
                mime_type = 'text/javascript'
            elif file_ext == '.css':
                mime_type = 'text/css'
            elif file_ext == '.html':
                mime_type = 'text/html'
            elif file_ext == '.json':
                mime_type = 'application/json'
            elif file_ext == '.xml':
                mime_type = 'application/xml'
            elif file_ext == '.csv':
                mime_type = 'text/csv'
            elif file_ext == '.md':
                mime_type = 'text/markdown'
            elif file_ext == '.yaml' or file_ext == '.yml':
                mime_type = 'text/yaml'
            elif file_ext == '.toml':
                mime_type = 'text/toml'
            elif file_ext == '.ini':
                mime_type = 'text/ini'
            elif file_ext == '.bat':
                mime_type = 'text/plain'
            elif file_ext == '.sh':
                mime_type = 'text/x-shellscript'
            elif file_ext == '.ps1':
                mime_type = 'text/x-powershell'
            elif file_ext == '.psm1':
                mime_type = 'text/x-powershell'
            elif file_ext == '.ps1xml':
                mime_type = 'text/x-powershell'
                    
                    
                    
            
            script = """
            (async function() {
                try {
                    const editor = document.querySelector('#prompt-textarea');
                    if (!editor) {
                        console.log("Editor not found");
                        return false;
                    }
                    
                    // convert Base64 data to Blob
                    const base64Data = '%s';
                    const byteCharacters = atob(base64Data);
                    const byteArrays = [];
                    
                    for (let offset = 0; offset < byteCharacters.length; offset += 512) {
                        const slice = byteCharacters.slice(offset, offset + 512);
                        const byteNumbers = new Array(slice.length);
                        for (let i = 0; i < slice.length; i++) {
                            byteNumbers[i] = slice.charCodeAt(i);
                        }
                        const byteArray = new Uint8Array(byteNumbers);
                        byteArrays.push(byteArray);
                    }
                    
                    const blob = new Blob(byteArrays, {type: '%s'});
                    const file = new File([blob], '%s', {type: '%s'});
                    
                    const dataTransfer = new DataTransfer();
                    dataTransfer.items.add(file);
                    
                    // focus on element
                    editor.focus();
                    
                    // create Paste event
                    const pasteEvent = new ClipboardEvent('paste', {
                        bubbles: true,
                        cancelable: true,
                        composed: true,
                        clipboardData: dataTransfer
                    });
                    
                    editor.dispatchEvent(pasteEvent);
                    
                    return true;
                } catch (error) {
                    console.error('Error:', error);
                    return false;
                }
            })();
            """ % (image_base64, mime_type, os.path.basename(filename), mime_type)
            
            result = tab.Runtime.evaluate(expression=script, awaitPromise=True)
            success = result.get('result', {}).get('value', False)
            
            if success:
                logger.info(f"Successfully pasted file: {filename}")
            else:
                logger.warning(f"Failed to paste file: {filename}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error pasting file: {e}")
            logger.error(traceback.format_exc())
            return False

    def send_query(self, browser, tab, text):
        """
        Send a text query to ChatGPT.
        """
        try:
            browser.activate_tab(tab.id)
            time.sleep(0.5)
            if not text.strip():
                logger.warning("Empty query text")
                return False
                
            # use updated selector to find text area
            js_code = r"""
            (function() {
                // in the latest ChatGPT interface, ProseMirror editor is used
                const editor = document.querySelector('.ProseMirror');
                if (!editor) return false;
                
                // focus on editor
                editor.focus();
                
                // ChatGPT ProseMirror editor uses contenteditable attribute
                // method for inserting content
                editor.innerHTML = `<p>${`%s`.replace('\\', '\\\\').replace('`', '\\`').replace("'", "\\'").replace('"', '\\"')}</p>`;
                
                // trigger input event
                const event = new Event('input', { bubbles: true });
                editor.dispatchEvent(event);
                
                return true;
            })();
            """ % text.replace('\\', '\\\\').replace('`', '\\`').replace("'", "\\'").replace('"', '\\"')
            
            result = tab.Runtime.evaluate(expression=js_code)
            success = result.get('result', {}).get('value', False)
            
            if not success:
                logger.warning("Failed to set text in editor")
                return False
                
            # check file upload status and wait
            max_wait_time = 30  # maximum 30 seconds
            wait_interval = 0.5  # 0.5 seconds interval
            start_time = time.time()
            
            while time.time() - start_time < max_wait_time:
                # check file upload status
                js_code = """
                (function() {
                    // check upload progress indicator
                    const uploadIndicator = document.querySelector('.upload-progress-indicator');
                    if (uploadIndicator) {
                        return false; // uploading
                    }
                    
                    // check file processing message
                    const processingElement = document.querySelector('.file-processing-message');
                    if (processingElement) {
                        return false; // file processing
                    }
                    
                    // check if file thumbnail or preview is fully loaded
                    const fileAttachments = document.querySelectorAll('.file-attachment');
                    if (fileAttachments.length > 0) {
                        // check if each file attachment is fully loaded
                        for (const attachment of fileAttachments) {
                            if (attachment.classList.contains('uploading') || 
                                attachment.classList.contains('processing')) {
                                return false; // still uploading/processing
                            }
                        }
                    }
                    
                    // check if send button is enabled - if disabled, it means still uploading
                    const sendButton = document.querySelector('button[data-testid="send-button"]');
                    if (sendButton && sendButton.disabled) {
                        return false; // button disabled = still uploading
                    }
                    
                    // all checks passed = upload complete
                    return true;
                })();
                """
                
                result = tab.Runtime.evaluate(expression=js_code)
                upload_complete = result.get('result', {}).get('value', False)
                
                if upload_complete:
                    logger.info("File uploads completed, proceeding to send message")
                    break
                
                # if still uploading, wait
                time.sleep(wait_interval)
                
                # intermediate log (every 5 seconds)
                if (time.time() - start_time) % 5 < wait_interval:
                    logger.info("Waiting for file uploads to complete...")
            
            # additional safety wait time (after upload complete)
            time.sleep(1)
            
            # update send button selector
            js_code = """
            (function() {
                // selector for send button according to current UI
                const sendButton = document.querySelector('button[data-testid="send-button"]');
                if (!sendButton) {
                    // try alternative selector
                    const alternativeButton = document.querySelector('button.absolute.bottom-0');
                    if (!alternativeButton) return false;
                    if (alternativeButton.disabled) return false;
                    alternativeButton.click();
                    return true;
                }
                
                if (sendButton.disabled) return false;
                sendButton.click();
                return true;
            })();
            """
            
            result = tab.Runtime.evaluate(expression=js_code)
            success = result.get('result', {}).get('value', False)
            
            if success:
                logger.info(f"Query sent successfully: {text[:50]}...")
            else:
                logger.warning("Failed to click send button")
                
                # retry send button click (1 time)
                logger.info("Retrying send button click after short delay...")
                time.sleep(2)  # additional wait
                
                # check button status before retry
                js_check = """
                (function() {
                    const sendButton = document.querySelector('button[data-testid="send-button"]');
                    if (!sendButton) return "button not found";
                    return sendButton.disabled ? "button disabled" : "button ready";
                })();
                """
                check_result = tab.Runtime.evaluate(expression=js_check)
                button_status = check_result.get('result', {}).get('value', "unknown")
                logger.info(f"Send button status: {button_status}")
                
                # retry
                result = tab.Runtime.evaluate(expression=js_code)
                success = result.get('result', {}).get('value', False)
                
                if success:
                    logger.info("Send button click successful on retry")
                else:
                    logger.warning("Send button click failed even after retry")
                
            return success
                
        except Exception as e:
            logger.error(f"Error sending query: {e}")
            logger.error(traceback.format_exc())
            return False

    def is_send_button_available(self, tab):
        """
        Check if send button is enabled.
        """
        try:
            js_code = """
            (function() {
                const sendButton = document.querySelector('button[data-testid="send-button"]');
                if (!sendButton) return false;
                return !sendButton.disabled;
            })();
            """
            
            result = tab.Runtime.evaluate(expression=js_code)
            return result.get('result', {}).get('value', False)
            
        except Exception as e:
            logger.error(f"Error checking send button: {e}")
            return False

    def is_model_responding(self, tab):
        """
        Check if model is currently responding.
        Implement more efficient DOM checks.
        """
        try:
            js_code = """
            (function() {
                // perform fastest check first - check stop button
                const stopButton = document.querySelector('button[data-testid="stop-button"]');
                if (stopButton) return true;
                
                // check ongoing indicator with more efficient selectors
                return document.querySelector('.text-token-text-streaming') !== null;
            })();
            """
            
            result = tab.Runtime.evaluate(expression=js_code)
            return result.get('result', {}).get('value', False)
            
        except Exception as e:
            logger.error(f"Error checking if model is responding: {e}")
            return False

    def wait_for_response_complete(self, tab, timeout=180):  # decrease timeout (300 seconds → 180 seconds)
        """
        Wait for model response to complete.
        Optimize response waiting logic.
        """
        try:
            start_time = time.time()
            last_log_time = start_time
            polling_interval = 0.2  # initial polling interval
            consecutive_inactive = 0  # number of consecutive inactive responses
            
            # check if model is responding - decrease timeout
            response_started = False
            response_start_timeout = 15  # 15 seconds wait for response start (30 seconds → 15 seconds)
            
            while time.time() - start_time < response_start_timeout and not response_started:
                if self.is_model_responding(tab):
                    response_started = True
                    logger.info("Model started responding")
                    break
                
                time.sleep(0.3)  # decrease polling interval (0.5 seconds → 0.3 seconds)
            
            if not response_started:
                logger.warning("Model did not start responding within timeout")
                return False
            
            # now wait for response to complete - apply more efficient dynamic polling
            while time.time() - start_time < timeout:
                is_responding = self.is_model_responding(tab)
                
                if not is_responding:
                    consecutive_inactive += 1
                    # check if there is no response for 3 times in a row - ensure stability
                    if consecutive_inactive >= 3:
                        logger.info("Response completed")
                        return True
                else:
                    consecutive_inactive = 0
                
                # log progress every 30 seconds
                current_time = time.time()
                if current_time - last_log_time > 30:
                    elapsed = int(current_time - start_time)
                    logger.info(f"Still waiting for response... ({elapsed}s elapsed)")
                    last_log_time = current_time
                
                # dynamic polling interval (check more frequently if responding, otherwise increase interval)
                polling_interval = 0.2 if is_responding else min(1.0, polling_interval * 1.5)
                time.sleep(polling_interval)
            
            logger.warning(f"Timeout waiting for response completion after {timeout}s")
            return False
            
        except Exception as e:
            logger.error(f"Error waiting for response: {e}")
            logger.error(traceback.format_exc())
            return False

    def get_last_python_code(self, tab):
        """
        Get last Python code block.
        Improved to work even if HTML structure changes.
        """
        try:
            js_code = """
            (function() {
                // try multiple selectors to find code block
                let codeBlocks = document.querySelectorAll('code.hljs.language-python');
                
                // if first selector not found, try other selectors
                if (codeBlocks.length === 0) {
                    codeBlocks = document.querySelectorAll('pre code.language-python');
                }
                
                if (codeBlocks.length === 0) {
                    // find general code tag
                    const allCodeBlocks = document.querySelectorAll('pre code');
                    // filter blocks that look like Python code
                    codeBlocks = Array.from(allCodeBlocks).filter(block => {
                        const text = block.textContent;
                        return text.includes('import') || text.includes('def ') || 
                            text.includes('class ') || text.includes('if __name__');
                    });
                }
                
                if (codeBlocks.length === 0) return '';
                
                // return last code block
                return codeBlocks[codeBlocks.length - 1].textContent;
            })();
            """
            
            result = tab.Runtime.evaluate(expression=js_code)
            code = result.get('result', {}).get('value', "")
            
            if code:
                logger.info(f"Found Python code ({len(code)} characters)")
            else:
                logger.warning("No Python code found")
                
            return code
            
        except Exception as e:
            logger.error(f"Error getting Python code: {e}")
            return ""

    def summery_answer(self, browser, tab, rsltstrpost, comment_of_this_cmd, simplify_command):
        """
        Send command execution results to ChatGPT-4o-mini to get summary information.
        
        Args:
            browser2: Browser object (ChatGPT-4o-mini tab)
            tab2: Browser tab object (ChatGPT-4o-mini tab)
            rsltstrpost: Command execution result string
        
        Returns:
            Structured result summary string
        """
        try:
            # write prompt for summarizing command results
            prompt = f"""

    Remove excessively repeated sentences and delete unnecessary content. If successful, clearly indicate that the task has succeeded according to the goal.
    In case of failure, clearly provide the cause of failure.
    ```
    Purpose of this command:
    {comment_of_this_cmd}

    Result of this command:
    {rsltstrpost}

    Summary command for this command:
    {simplify_command}
    ```

    Please respond exactly in the following format:
    purpose of command: [purpose of the command]
    success : "success" | "failed"
    error: False | true
    error status: [if there is an error, explain the error content, otherwise 'no error']
    summary of output: [summary of the entire result]


    The response must contain exactly only the above format. Do not include other explanations or text."""

            # send prompt to ChatGPT-4o-mini
            logger.info("Sending command results to ChatGPT-4o-mini for summarization")
            self.send_query(browser, tab, prompt)
            
            # wait for response - summary can be generated relatively quickly, so reduce timeout
            if not self.wait_for_response_complete(tab, timeout=90):
                logger.warning("Summary response waiting timed out")
                return "Summary generation timeout"
                
            # extract ChatGPT response
            js_code = """
    (function() {
        try {
            // find response message using various selectors
            const selectors = [
                '.markdown.prose', 
                '.text-message .markdown',
                '[data-message-author-role="assistant"] .markdown',
                '.agent-turn .markdown',
                'article .prose',
                '.text-message'
            ];
            
            let lastMessage = null;
            for (const selector of selectors) {
                const elements = document.querySelectorAll(selector);
                if (elements.length > 0) {
                    lastMessage = elements[elements.length - 1];
                    break;
                }
            }
            
            if (!lastMessage) return 'No response message found';
            
            // try extracting code block (code tag with hljs class)
            const codeBlocks = lastMessage.querySelectorAll('code.hljs');
            if (codeBlocks && codeBlocks.length > 0) {
                return codeBlocks[codeBlocks.length - 1].textContent;
            }
            
            // check general code tag
            const codeElements = lastMessage.querySelectorAll('code');
            if (codeElements && codeElements.length > 0) {
                return codeElements[codeElements.length - 1].textContent;
            }
            
            // check pre tag
            const preElements = lastMessage.querySelectorAll('pre');
            if (preElements && preElements.length > 0) {
                // check code inside pre tag
                const preCodeElements = preElements[preElements.length - 1].querySelectorAll('code');
                if (preCodeElements && preCodeElements.length > 0) {
                    return preCodeElements[0].textContent;
                }
                return preElements[preElements.length - 1].textContent;
            }
            
            // extract general text (if all above methods fail)
            return lastMessage.textContent;
        } catch (error) {
            console.error('Error in summary extraction:', error);
            return 'Error: ' + error.toString();
        }
    })();
    """
            
            result = tab.Runtime.evaluate(expression=js_code)
            response_text = result.get('result', {}).get('value', "")
            
            if not response_text or response_text.startswith('Error:') or response_text == 'No response message found':
                logger.warning(f"No valid summary response found: {response_text}")
                return "No valid summary response found"
                
            logger.info(f"Summary generated ({len(response_text)} characters)")
            return response_text
            
        except Exception as e:
            logger.error(f"Error in summery_answer: {e}")
            logger.error(traceback.format_exc())
            return f"Error occurred in summary generation: {str(e)}"

    def execute_chatgpt_cmd_session(self, browser, tab, tab2, query):
        """
        Manage a session that sends user queries to ChatGPT, executes CMD commands, and exchanges results.

        Args:
            tab: Browser tab object
            query: Initial user query

        Returns:
            Final result string
        """
        try:
            logger.info(f"Starting ChatGPT CMD session with query: {query}")

            # get CmdManager instance from imported cmd_manager module
            cmd_manager = get_cmd_manager()
            print("cmd_manager", cmd_manager.uid)

            # initialize task completion flag file (delete if it exists)
            if os.path.exists("task_complete.flag"):
                os.remove("task_complete.flag")

            # send initial query
            cmd_result = cmd_manager.execute_command("echo %CD%", timeout=60)
            rsltstr = cmd_result['stdout'].strip()
            
            initial_prompt = f"""User request: Current directory path is {rsltstr} 
    Note: Always move to the working directory first before starting the actual work.
    {query}

    Please provide a step-by-step sequence of Windows CMD commands to perform this task.
    After executing the first command, we will provide the next command.
    If rsltstr_summried contains "success", we consider the previous task to be successful.
    The command is output in the following json format:

    {{ "aim": aim of this command,
    "cmd" : cmd code for aim , 
    "simplify_command": ask query for making answer for result of this command
    }}

    For example, if you want to search the list of files in D:,
    {{ "aim": "search list of files in D:",
    "cmd" : "dir d:",
    "simplify_command": "Please summarize the result of the command to best match the purpose."
    }}

    If the previous command is completed, please indicate it clearly in the following format:
    {{ "aim": "terminated",
    "cmd" : "terminated",
    "simplify_command": conclusion of result of this commands sequence
    }}

    Do not provide unnecessary explanations."""

            logger.info("Sending initial prompt to ChatGPT")
            self.send_query(browser, tab, initial_prompt)

            # wait for response
            if not self.wait_for_response_complete(tab, timeout=300):
                logger.warning("Initial response waiting timed out")
                return "Error: ChatGPT response waiting timeout"
            time.sleep(1)
            
            # command execution and result sending loop
            max_iterations = 15  # maximum iterations for safety
            iteration = 0
            final_result = ""
            answerFailed = False

            try:
                while iteration < max_iterations:
                    time.sleep(5)
                    iteration += 1
                    logger.info(f"Command iteration {iteration}/{max_iterations}")
                    
                    # check task completion flag file
                    if os.path.exists("task_complete.flag"):
                        logger.info("Task completion flag file found")
                        with open("task_complete.flag", "r") as f:
                            flag_content = f.read().strip()
                        if "##TASK_COMPLETE##" in flag_content:
                            logger.info("Task completed with completion flag")
                            final_result = "Task has been completed. Completion flag file has been created."
                            # read content of JSON status file
                            cmd_result = cmd_manager.execute_command('type task_complete.flag', timeout=60)
                            if cmd_result["success"]:
                                final_result += f"\n\nCompletion information: {cmd_result['stdout']}"
                            break
                    
                    # extract command from ChatGPT response
                    js_code = """
        (function() {
            // find response message using selectors
            const selectors = [
                '.markdown.prose', 
                '.text-message .markdown',
                '[data-message-author-role="assistant"] .markdown',
                '.agent-turn .markdown',
                'article .prose'
            ];
            
            let lastMessage = null;
            
            // try each selector
            for (const selector of selectors) {
                const elements = document.querySelectorAll(selector);
                if (elements.length > 0) {
                    lastMessage = elements[elements.length - 1];
                    break;
                }
            }
            
            // if message not found
            if (!lastMessage) {
                return '';
            }
            
            // extract message text
            const fullText = lastMessage.textContent || '';
            
            // try extracting JSON format command
            try {
                // extract JSON format (supports various formats)
                // 1. extract text that starts with { and ends with }
                const jsonRegex = /\\{[^\\{\\}]*"aim"\\s*:\\s*"[^"]*"[^\\{\\}]*"cmd"\\s*:\\s*"[^"]*"[^\\{\\}]*\\}/g;
                const jsonMatches = fullText.match(jsonRegex);
                
                if (jsonMatches && jsonMatches.length > 0) {
                    // return the last JSON format
                    return jsonMatches[jsonMatches.length - 1];
                }
                
                // 2. try extracting JSON from code block - check pre and code tag contents
                const codeElements = lastMessage.querySelectorAll('code');
                if (codeElements && codeElements.length > 0) {
                    // text content of the last code block
                    const codeText = codeElements[codeElements.length - 1].textContent;
                    // find JSON in the code block
                    const codeJsonMatches = codeText.match(jsonRegex);
                    if (codeJsonMatches && codeJsonMatches.length > 0) {
                        return codeJsonMatches[codeJsonMatches.length - 1];
                    }
                }
                
                // 3. extract code block from text using regular expression
                const codeBlockRegex = /```(?:json)?([^`]+)```/g;
                const codeMatches = [];
                let match;
                while ((match = codeBlockRegex.exec(fullText)) !== null) {
                    codeMatches.push(match[1].trim());
                }
                
                if (codeMatches.length > 0) {
                    const lastCodeBlock = codeMatches[codeMatches.length - 1];
                    // find JSON format in the code block content
                    const jsonInCodeRegex = /\\{[^\\{\\}]*"aim"\\s*:\\s*"[^"]*"[^\\{\\}]*"cmd"\\s*:\\s*"[^"]*"[^\\{\\}]*\\}/g;
                    const jsonInCodeMatches = lastCodeBlock.match(jsonInCodeRegex);
                    
                    if (jsonInCodeMatches && jsonInCodeMatches.length > 0) {
                        return jsonInCodeMatches[jsonInCodeMatches.length - 1];
                    }
                    
                    // return general code block if not JSON format
                    return lastCodeBlock;
                }
                
                // 4. check existing completion pattern
                const hasResult = 
                    fullText.includes('##TASK_COMPLETE##') || 
                    fullText.includes('{"status":"complete"') || 
                    fullText.includes('Agent work completed') ||
                    (fullText.includes('task_complete.flag') && fullText.includes('work completed')) ||
                    fullText.includes('"aim": "terminated"');
                
                if (hasResult) {
                    // return full text if it is a termination message
                    return fullText;
                }
                
                // return empty string if there is no JSON format and no code block
                return '';
                
            } catch (error) {
                // return original text if an error occurs
                console.error('JSON extraction error:', error);
                return fullText;
            }
        })();
        """
                    
                    result = tab.Runtime.evaluate(expression=js_code)
                    response_text = result.get('result', {}).get('value', "")
                    print("Command response:", response_text[:100])
                    
                    # check if there is a command in the response text or if it is a completion message
                    if any(marker in response_text for marker in [
                        "##TASK_COMPLETE##", 
                        "\"status\":\"complete\"", 
                        "Agent work completed", 
                        "\"aim\": \"terminated\""
                    ]):
                        logger.info("Task completion detected in response")
                        final_result = response_text
                        break
                        
                    # if there is a command extracted from the code block, execute it
                    cmd_to_execute = response_text.strip() if response_text else None
                    comment_of_this_cmd = ''
                    
                    
                    # extract cmd field from JSON
                    simplify_command = None
                    if answerFailed == False:
                        try:
                            # try extracting JSON format
                            json_pattern = r'\{.*"aim"\s*:\s*"[^"]*".*"cmd"\s*:\s*"[^"]*".*\}'
                            json_match = re.search(json_pattern, cmd_to_execute, re.DOTALL)
                            
                            if json_match:
                                json_str = json_match.group(0)
                                # normalize JSON string - check quotes and escape backslashes
                                json_str = json_str.replace("'", '"')
                                
                                # solve backslash problem
                                # 1. convert all backslashes to a temporary token
                                json_str = json_str.replace('\\', '___BACKSLASH___')
                                # 2. convert temporary token to escaped backslash
                                json_str = json_str.replace('___BACKSLASH___', '\\\\')
                                
                                # check JSON validity and normalize
                                try:
                                    # parse normalized JSON string
                                    json_data = json.loads(json_str)
                                    
                                    if "aim" in json_data and "cmd" in json_data:
                                        comment_of_this_cmd = json_data["aim"]
                                        cmd_to_execute = json_data["cmd"]
                                        simplify_command = json_data["simplify_command"]
                                        
                                        # check termination command
                                        if cmd_to_execute == "terminated":
                                            logger.info("Termination command detected")
                                            final_result = f"작업이 완료되었습니다.\n\n목표: {comment_of_this_cmd}"
                                            break
                                except json.JSONDecodeError as je:
                                    # try direct extraction if JSON parsing fails
                                    logger.warning(f"JSON parsing failed: {je}, trying direct extraction")
                                    
                                    # try direct extraction if JSON parsing fails
                                    aim_match = re.search(r'"aim"\s*:\s*"([^"]*)"', json_str)
                                    cmd_match = re.search(r'"cmd"\s*:\s*"([^"]*)"', json_str)
                                    simplify_command_match = re.search(r'"simplify_command"\s*:\s*"([^"]*)"', json_str)
                                    
                                    if aim_match and cmd_match:
                                        comment_of_this_cmd = aim_match.group(1)
                                        cmd_to_execute = cmd_match.group(1)
                                        cc = simplify_command_match.group(1)
                                        # check termination command
                                        if cmd_to_execute == "terminated":
                                            logger.info("Termination command detected")
                                            final_result = f"작업이 완료되었습니다.\n\n목표: {comment_of_this_cmd}"
                                            break
                        except Exception as e:
                            print(traceback.format_exc())
                            logger.warning(f"Error parsing JSON command: {e}")
                            # use original text if JSON parsing fails
                        
                        print("cmd_to_execute", cmd_to_execute)
                        
                        if not cmd_to_execute:
                            logger.warning("No command found in response")
                            self.send_query(browser, tab, "No command found in response. Please provide a clear JSON format.")
                            
                            if not self.wait_for_response_complete(tab, timeout=300):
                                logger.warning("Response waiting timed out")
                            continue
                    
                        # execute command
                        cmd_result = cmd_manager.execute_command("dir", timeout=60)
                        rsltstrpre = '---dir result before operation---\n'
                        rsltstrpre += cmd_result['stdout'].strip()
                        rsltstrpre += cmd_result['stderr'].strip()
                        
                        logger.info(f"Executing command: {cmd_to_execute}")
                        cmd_result = cmd_manager.execute_command(cmd_to_execute, timeout=300)
                        
                        cmd_resultpost = cmd_manager.execute_command("dir", timeout=60)
                        rsltstrpost = '\n\n---dir result after operation---\n'
                        rsltstrpost += cmd_resultpost['stdout'].strip()
                        rsltstrpost += cmd_resultpost['stderr'].strip()
                        
                        rsltstr_summried = self.summery_answer(browser, tab2, rsltstrpost, comment_of_this_cmd, simplify_command)
                        print("rsltstr_summried", rsltstr_summried)
                            
                        # prepare execution result
                        if True:  # cmd_result["success"]:
                            # format result
                            formatted_output = cmd_result.get('formatted_output', '')
                            
                            # if there is no format, use previous method
                            if not formatted_output:
                                rsltstr = "----stdout---\n" + cmd_result['stdout'] + "\n\n---stderr---\n" + cmd_result['stderr']
                                result_message = f"""
            ----Agent's final goal----
            {query}
            ----Current command execution result----
            {rsltstr}

            ----Result summary----
            {rsltstr_summried}
            
            If rsltstr_summried contains "success", we consider the previous task to be successful.
            Check if the desired task has been executed through the result summary,
            
            Please suggest the next command considering the next task.
            
            If you did not get the desired content through the result summary, clearly present how and why to modify the simplify_command to reduce the logs

            The command is output in the following json format:

            {{ "aim": aim of this command,
            "cmd" : cmd code for aim , 
            "simplify_command": additional query for making "a truncate not necessary logs for rsltstr of this command, explain how to remove not necessary logs and why 
            }}

            For example, if you want to search the list of files in D:,
            {{ "aim": "search list of files in D:",
            "cmd" : "dir d:",
            "simplify_command": "d:디렉토리의 파일목록을 조회한 결과를 제공하오니 Please summarize to best match the purpose.The summary includes the following content....(설명)"
            }}

            If the previous command is completed, please indicate it clearly in the following format:
            {{ "aim": "terminated",
            "cmd" : "terminated",
            "simplify_command": "terminated"
            }}
            """
                            else:
                                # use new format
                                result_message = f"""
            ----Agent's final goal----
            {query}

            ----Current command execution result----
            {formatted_output}

            ----Result summary----
            {rsltstr_summried}

            If rsltstr_summried contains "success", we consider the previous task to be successful.
            Check if the desired task has been executed through the result summary,
            
            Please suggest the next command considering the next task.
            
            If you did not get the desired content through the result summary, clearly present how and why to modify the simplify_command to reduce the logs

            The command is output in the following json format:

            {{ "aim": aim of this command,
            "cmd" : cmd code for aim , 
            "simplify_command": additional query for making "a truncate not necessary logs for rsltstr of this command, explain how to remove not necessary logs and why 
            }}

            For example, if you want to search the list of files in D:,
            {{ "aim": "search list of files in D:",
            "cmd" : "dir d:",
            "simplify_command": "d:디렉토리의 파일목록을 조회한 결과를 제공하오니 Please summarize to best match the purpose.The summary includes the following content....(설명)"
            }}

            If the previous command is completed, please indicate it clearly in the following format:
            {{ "aim": "terminated",
            "cmd" : "terminated",
            "simplify_command": "terminated"
            }}
            """
                        else:
                                result_message = """ need to be modified"""
                                
                    # send result
                    self.send_query(browser, tab, result_message)
                    
                    # wait for response
                    if not self.wait_for_response_complete(tab, timeout=300):
                        logger.warning("Response waiting timed out")
                        continue

                    # check task completion flag file again
                    if os.path.exists("task_complete.flag"):
                        logger.info("Task completion flag file found after response")
                        with open("task_complete.flag", "r") as f:
                            flag_content = f.read().strip()
                        if "##TASK_COMPLETE##" in flag_content:
                            logger.info("Task completed with completion flag")
                            final_result = "Task has been completed. Completion flag file has been created."
                            # read content of JSON status file
                            cmd_result = cmd_manager.execute_command('type task_complete.flag', timeout=60)
                            if cmd_result["success"]:
                                final_result += f"\n\nCompletion information: {cmd_result['stdout']}"
                            break

                if not final_result and iteration >= max_iterations:
                    logger.warning("Maximum iterations reached without completion")
                    final_result = "Maximum number of iterations reached. The task may not have been completed."
                    
                # add visual separation when final result is printed
                logger.info("=" * 50)
                logger.info("Task status: Completed" if "Task has been completed" in final_result else "Task status: Incomplete")
                logger.info("=" * 50)
                
                # create task result summary
                summary = "== Task result summary ==\n"
                if os.path.exists("task_complete.flag"):
                    with open("task_complete.flag", "r") as f:
                        flag_content = f.read().strip()
                    summary += f"Completion status: Success\nCompletion tag: {flag_content}\n"
                else:
                    summary += "Completion status: Incomplete or failed\n"
                
                # final directory status
                cmd_result = cmd_manager.execute_command("dir", timeout=60)
                summary += f"\nFinal directory status:\n{cmd_result['stdout'][:500]}...\n"
                
                logger.info(summary)
                return final_result + "\n\n" + summary
                
            except Exception as e:
                answerFailed = True
                logger.error(f"Error in command execution loop: {e}")
                logger.error(traceback.format_exc())
                return f"Error occurred during command execution: {str(e)}"
            
        except Exception as e:
            logger.error(f"Error in execute_chatgpt_cmd_session: {str(e)}")
            logger.error(traceback.format_exc())
            return f"Error occurred: {str(e)}"

    def extract_command_from_response(self, response_text):
        """
        Extract CMD command to execute from ChatGPT response.
        
        Args:
            response_text: ChatGPT response text
            
        Returns:
            Extracted command string or empty string
        """
        try:
            # try extracting command from code block
            import re
            print("response_text", response_text)
            # code block pattern (all forms of code surrounded by ```)
            code_block_pattern = r'```(?:cmd|bat|bash|shell|powershell|)?\s*(.*?)\s*```'
            code_blocks = re.findall(code_block_pattern, response_text, re.DOTALL)
            
            if code_blocks:
                # use the last code block
                cmd = code_blocks[-1].strip()
                logger.info(f"Found command in code block: {cmd}")
                return cmd
            
            # if there is no code block, find command in regular text
            lines = response_text.split('\n')
            
            # list of Windows CMD commands
            common_cmd_prefixes = [
                'dir', 'cd', 'copy', 'del', 'echo', 'type', 'mkdir', 'rmdir', 
                'ping', 'ipconfig', 'netstat', 'tasklist', 'findstr', 'systeminfo',
                'ver', 'chdir', 'cls', 'date', 'time', 'rd', 'md', 'ren', 'move'
            ]
            
            # recognize command by command indicator
            cmd_indicators = ["명령어:", "실행:", "CMD:", "명령:", "커맨드:", "command:", "다음 명령어:"]
            for line in lines:
                for indicator in cmd_indicators:
                    if indicator.lower() in line.lower():
                        cmd = line.split(indicator, 1)[1].strip()
                        logger.info(f"Found command with indicator: {cmd}")
                        return cmd
            
            # recognize command by common CMD prefixes
            for line in lines:
                line_stripped = line.strip()
                for prefix in common_cmd_prefixes:
                    # command format: 'dir', 'dir C:\', 'cd /d C:\' etc.
                    if re.match(f"^{prefix}\\b", line_stripped, re.IGNORECASE):
                        logger.info(f"Found command by prefix: {line_stripped}")
                        return line_stripped
            
            # recognize command by quoted command
            quoted_cmd_pattern = r'["\']([^"\']+?)["\']'
            for line in lines:
                line_stripped = line.strip()
                quoted_matches = re.findall(quoted_cmd_pattern, line_stripped)
                for match in quoted_matches:
                    for prefix in common_cmd_prefixes:
                        if re.match(f"^{prefix}\\b", match, re.IGNORECASE):
                            logger.info(f"Found command in quotes: {match}")
                            return match
            
            logger.warning("No command found in response")
            logger.debug(f"Response content: {response_text[:500]}...")
            return ""
            
        except Exception as e:
            logger.error(f"Error extracting command: {e}")
            logger.error(traceback.format_exc())
            return ""

    def cmd_session_main(self):
        """
        Main function for CMD session
        """
        try:
            # Get user input
            print("Input query?")
            user_query = input("Enter a query for CMD task: ")
            
            # Check if browser is already started, only verify page load
            if not self.tab:
                logger.error("No main tab available")
                return
                
            # Check page load
            if not self.check_page_loaded(self.tab, timeout=15):
                logger.error("Page load check failed")
                return
                
            # Execute CMD session
            result = self.execute_chatgpt_cmd_session(self.browser, self.tab, self.tab2, user_query)
            
            # Output results
            print("\n--- Task result ---")
            print(result)
            
        except Exception as e:
            logger.error(f"Unexpected error in CMD session: {e}")
            logger.error(traceback.format_exc())
        finally:
            # Safely cleanup tabs (don't close browser)
            logger.info("CMD session completed, cleaning up tabs")

    def newmain(self):
        try:
            # Select operation mode (maintain existing features while adding CMD session)
            print("Select operation mode:")
            print("1. Code analysis and modification (existing feature)")
            print("2. CMD command execution session")
            
            mode = "2"
            if mode == "2":
                self.cmd_session_main()
            else:
                # Existing main function content (code analysis and modification)
                # Browser already started, only check page load
                if not self.tab:
                    logger.error("No main tab available")
                    return
                
                # Check page load - shorter timeout
                if not self.check_page_loaded(self.tab, timeout=15):  # Reduced timeout (30s -> 15s)
                    logger.error("Page load check failed")
                    return
                    
                # Send test query
                logger.info("Sending test query...")
                self.send_query(self.browser, self.tab, "Please tell me about today's weather:")
                
                # Wait for response - shorter timeout
                if not self.wait_for_response_complete(self.tab, timeout=180):  # Reduced timeout (300s -> 180s)
                    logger.warning("Response waiting timed out")
                
                # Get code
                python_code = self.get_last_python_code(self.tab)
                if python_code:
                    # Save result code
                    with open("fixed_code.py", "w", encoding="utf-8") as f:
                        f.write(python_code)
                    logger.info("Code saved to fixed_code.py")
            
        except Exception as e:
            logger.error(f"Unexpected error in main: {e}")
            logger.error(traceback.format_exc())
        finally:
            logger.info("Exiting program")

    def safely_close_tab(self, browser, tab):
        """
        Safely close a tab
        """
        try:
            if tab and hasattr(tab, 'id') and tab.id:
                return self.complete_tab_cleanup(browser, tab)
            else:
                logger.warning("Cannot safely close invalid tab")
                return False
        except Exception as e:
            logger.error(f"Error in safely_close_tab: {e}")
            return False

    def extract_useful_content_from_text(self, text):
        """
        Extract and structure useful information from text response.
        Can extract information from regular text as well as JSON format.
        """
        result = {
            "page_structure": "",
            "target_elements": [],
            "selectors": {},
            "crawling_method": "",
            "python_code": "",
            "javascript_handling": "",
            "dynamic_content": "",
            "analysis_complete": True,
            "additional_instructions": ""
        }
        # ... existing code ...

    def test_crawl_functionality(self, analysis_result, url, test_string):
        """
        Test actual crawling based on analysis results.
        Execute directly in browser environment through Chrome DevTools Protocol.
        
        Args:
            analysis_result: Crawling analysis result dictionary
            url: URL to test
            test_string: Test string to find in crawling results
            
        Returns:
            Dictionary containing test results
        """
        
    def complete_tab_cleanup(self, browser, tab):
        """
        Complete tab cleanup. Release all related resources and cleanup WebSocket connections.
        
        Args:
            browser: Browser object
            tab: Tab object to cleanup
            
        Returns:
            Success status
        """
        
    def safely_close_all_tabs(self):
        """
        Safely close all open tabs
        """


if __name__ == "__main__":
    import sys
    
    # Set up test mode
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("Running in test mode - testing WebSocket handling")
        try:
            client = ChromeCDPClient()
            print("ChromeCDPClient initialization successful")
            print("WebSocket patching was applied successfully")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Test failed: {e}")
            logger.error(traceback.format_exc())
            sys.exit(1)
    
    # Regular mode    
    os.chdir("d:")
    client = ChromeCDPClient()
    try:
        client.newmain()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        logger.error(traceback.format_exc())
    finally:
        # close all tabs before program termination
        try:
            if hasattr(client, 'safely_close_all_tabs'):
                client.safely_close_all_tabs()
        except Exception as e:
            logger.error(f"Error during final tab cleanup: {e}")
        logger.info("Program terminated")
