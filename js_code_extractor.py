"""
JavaScript Code Extractor - Helper module

This module provides functions to extract JavaScript code from ChatGPT responses
using Python's regex functionality instead of relying on JavaScript regex.
"""

import re
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

def extract_js_from_html(tab):
    """
    Extract JavaScript code from ChatGPT response in the browser tab
    using Python-side approach with simpler browser DOM queries.
    
    Args:
        tab: The browser tab object containing ChatGPT responses
        
    Returns:
        Extracted JavaScript code or empty string if none found
    """
    try:
        # Get all potential code elements from the page - no regex in JS
        js_getter = """
        (function() {
            try {
                // Object to store all potential code blocks
                const result = {
                    languageBlocks: [],
                    preBlocks: [],
                    markdownText: ""
                };
                
                // 1. Get code blocks with language class
                const jsCodeElements = document.querySelectorAll('pre code.language-javascript, pre code.hljs.language-javascript');
                for (let i = 0; i < jsCodeElements.length; i++) {
                    result.languageBlocks.push(jsCodeElements[i].textContent);
                }
                
                // 2. Get all pre elements
                const preElements = document.querySelectorAll('pre');
                for (let i = 0; i < preElements.length; i++) {
                    result.preBlocks.push(preElements[i].textContent);
                }
                
                // 3. Get markdown content for manual parsing
                const markdownElements = document.querySelectorAll('.markdown');
                if (markdownElements.length > 0) {
                    result.markdownText = markdownElements[markdownElements.length - 1].textContent;
                }
                
                return JSON.stringify(result);
            } catch (error) {
                return JSON.stringify({error: error.toString()});
            }
        })();
        """
        
        # Execute the code in the browser
        result = tab.Runtime.evaluate(expression=js_getter)
        result_json = result.get('result', {}).get('value', "{}")
        
        import json
        code_data = json.loads(result_json)
        
        # Check for errors
        if 'error' in code_data:
            logger.warning(f"Error in JS extraction: {code_data['error']}")
            return ""
            
        # Process in order of preference
        
        # 1. Check language-specific code blocks (most reliable)
        if code_data.get('languageBlocks'):
            js_code = code_data['languageBlocks'][-1]
            logger.info(f"Found JavaScript code block with language class ({len(js_code)} chars)")
            return js_code
            
        # 2. Check pre blocks for JavaScript patterns
        for pre_text in code_data.get('preBlocks', []):
            if any(pattern in pre_text for pattern in [
                'async function', 'function(', 'return {', 'document.querySelector'
            ]):
                logger.info(f"Found JavaScript code in pre block ({len(pre_text)} chars)")
                return pre_text
                
        # 3. Use regex to find code blocks in markdown text
        markdown_text = code_data.get('markdownText', "")
        if markdown_text:
            # Try to find ```javascript blocks first
            js_pattern = r'```(?:javascript|js)(.*?)```'
            js_matches = re.findall(js_pattern, markdown_text, re.DOTALL)
            
            if js_matches:
                js_code = js_matches[-1].strip()
                logger.info(f"Found JavaScript code in ```javascript block ({len(js_code)} chars)")
                return js_code
                
            # Then try generic code blocks
            code_pattern = r'```(.*?)```'
            code_matches = re.findall(code_pattern, markdown_text, re.DOTALL)
            
            for code in code_matches:
                code = code.strip()
                if any(pattern in code for pattern in [
                    'async function', 'function(', 'return {', 'document.querySelector'
                ]):
                    logger.info(f"Found JavaScript code in generic ``` block ({len(code)} chars)")
                    return code
        
        logger.warning("No JavaScript code found in ChatGPT response")
        return ""
        
    except Exception as e:
        logger.error(f"Error extracting JavaScript: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return ""

def clean_js_code(code):
    """
    Clean and validate JavaScript code by removing markdown code markers
    and normalizing the format.
    
    Args:
        code: The raw JavaScript code string
        
    Returns:
        Cleaned JavaScript code
    """
    if not code:
        return ""
        
    # Remove markdown code markers if present
    if code.startswith('```javascript') and code.endswith('```'):
        code = code[13:-3].strip()
    elif code.startswith('```js') and code.endswith('```'):
        code = code[5:-3].strip()
    elif code.startswith('```') and code.endswith('```'):
        code = code[3:-3].strip()
        
    return code

def extract_and_clean_js(tab):
    """
    Convenience function to extract and clean JavaScript code
    from a browser tab in one step.
    
    Args:
        tab: The browser tab object
        
    Returns:
        Clean JavaScript code or empty string
    """
    raw_code = extract_js_from_html(tab)
    return clean_js_code(raw_code) 