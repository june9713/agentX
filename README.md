# Chrome Debug Console MCP

크롬 브라우저의 DevTools 프로토콜(CDP)을 이용하여 MCP(Model Context Protocol) 서버를 통해 크롬 디버그 콘솔을 제어할 수 있는 도구입니다.

## 기능

- 크롬 브라우저에 연결 및 탭 관리
- JavaScript 코드 실행
- DOM 요소 선택 및 정보 추출
- 페이지 이동
- 스크린샷 캡처

## 설치 및 실행

### 요구 사항
- Python 3.8 이상
- 크롬 브라우저(원격 디버깅 모드 활성화)

### 설치

```bash
pip install -r requirements.txt
```

### 크롬 브라우저 원격 디버깅 모드 실행

Windows에서:
```bash
"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222
```

macOS에서:
```bash
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222
```

Linux에서:
```bash
google-chrome --remote-debugging-port=9222
```

### MCP 서버 실행

```bash
python server.py
```

## 사용 방법

1. 크롬 브라우저를 원격 디버깅 모드로 실행합니다.
2. MCP 서버를 실행합니다.
3. 다음 MCP 도구(Tools)를 통해 크롬 브라우저를 제어할 수 있습니다:

### 크롬 연결 및 탭 관리

```python
# 크롬 브라우저에 연결
chrome_connect(port=9222, host="localhost")

# 열린 탭 목록 확인
chrome_list_tabs()
```

### JavaScript 코드 실행

```python
# JavaScript 코드 실행
chrome_evaluate("document.title")
chrome_evaluate("document.querySelector('h1').textContent")
chrome_evaluate("window.location.href")
```

### DOM 요소 조작

```python
# DOM 요소 가져오기
chrome_get_dom("h1")
chrome_get_dom("#main")
chrome_get_dom(".navbar")
```

### 페이지 이동

```python
# 다른 URL로 이동
chrome_navigate("https://www.google.com")
```

### 스크린샷 캡처

```python
# 현재 페이지 스크린샷 캡처
chrome_screenshot()

# 특정 경로에 스크린샷 저장
chrome_screenshot(save_path="my_screenshot.png")
```

## Chrome DevTools Protocol 참고 자료

크롬 DevTools 프로토콜에 대한 자세한 내용은 다음 링크를 참조하세요:
- [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [Chrome DevTools Protocol Viewer](https://chromedevtools.github.io/devtools-protocol/tot/)

## 라이센스

MIT License 