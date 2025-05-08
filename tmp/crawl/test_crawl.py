
# 크롤링 결과 저장 코드
def save_crawl_result(result_data):
    import json
    import os
    
    # 결과를 문자열로 변환
    if isinstance(result_data, (list, dict)):
        try:
            result_str = json.dumps(result_data, ensure_ascii=False, indent=2)
        except:
            result_str = str(result_data)
    else:
        result_str = str(result_data)
    
    # 결과 저장
    with open('./tmp/crawl/crawl_result_data.txt', 'w', encoding='utf-8') as f:
        f.write(result_str)
    
    # 성공 여부 반환
    return True

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import time

options = Options()
options.add_argument('--headless')
options.add_argument('--disable-gpu')
driver = webdriver.Chrome(options=options, executable_path='D:/workspace/python/2025/agentX/Scripts/chromedriver.exe')

video_url = 'https://www.youtube.com/watch?v=o7wf2b2CRc4'
driver.get(video_url)
time.sleep(5)  # JS 로딩 시간 확보

# 설명란 추출
try:
    description = driver.find_element(By.CSS_SELECTOR, '#description').text
except:
    description = '설명란을 찾을 수 없음'

# 자동 생성 챕터 추출 (있는 경우)
chapters = []
try:
    chapters_elements = driver.find_elements(By.CSS_SELECTOR, 'ytd-engagement-panel-section-list-renderer[section-identifier="engagement-panel-macro-markers"] ytd-macro-markers-list-item-renderer')
    for el in chapters_elements:
        title = el.find_element(By.CSS_SELECTOR, '#marker-title').text
        timestamp = el.find_element(By.CSS_SELECTOR, '#time').text
        chapters.append(f"{timestamp} - {title}")
except:
    chapters = ['자동 생성 챕터 없음 또는 접근 불가']

print('요약:', description)
print('챕터:', chapters)
driver.quit()

# 크롤링 결과 저장
save_crawl_result(locals().get('result', locals()))