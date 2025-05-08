import re

a = """{
  "page_structure": "The HTML file represents the Korean version of Google's main search page. It contains numerous embedded scripts responsible for UI behavior, analytics, and dynamic content loading. There are no static 'Google Maps' elements within this HTML; however, the JS file appears to support dynamic script policy evaluation, potentially used for loading Google Maps on demand.",
  "target_elements": ["지명 (place name)", "건물명 (building name)", "GPS 좌표 (latitude, longitude)"],
  "selectors": {
    "search_box": "input[name='q']",
    "search_results": "div#search div.g",
    "map_link": "a[href*='google.com/maps']"
  },
  "crawling_method": "1. Perform a search query on Google using the search box (e.g., for a place or building name).\n2. Wait for the results to load dynamically (requires headless browser or Selenium).\n3. Extract any Google Maps links containing GPS coordinates from anchor tags.",
  "python_code": "from selenium import webdriver\nfrom selenium.webdriver.chrome.options import Options\nfrom urllib.parse import urlparse, parse_qs\nimport time\n\noptions = Options()\noptions.add_argument('--headless')\ndriver = webdriver.Chrome(options=options)\ndriver.get('https://www.google.com')\n\nsearch_box = driver.find_element('name', 'q')\nsearch_box.send_keys('서울타워')\nsearch_box.submit()\n\ntime.sleep(3)\n\nlinks = driver.find_elements('css selector', 'a[href*=\"google.com/maps\"]')\nfor link in links:\n    href = link.get_attribute('href')\n    print(href)\n\ndriver.quit()",
  "javascript_handling": "Use Selenium or Puppeteer to render JavaScript. The JS file shows that Google uses `trustedTypes`, `createPolicy`, and dynamic eval(), meaning conventional static crawlers like `requests` or `BeautifulSoup` won't work.",
  "dynamic_content": "Content like Maps links or GPS coordinates appears only after DOM updates via JavaScript. Thus, full headless browser rendering is necessary.",
  "analysis_complete": true,
  "additional_instructions": ""
}
"""

exr = r'''(\{(?:[^{}]|(?:\{(?:[^{}]|(?:\{[^{}]*\}))*\}))*\})'''

print(re.findall(exr, a))
print(len(re.findall(exr, a)))
