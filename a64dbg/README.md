# a64dbg - Frida-Python 기반 디버깅 자동화 프레임워크

## 개요

a64dbg는 Frida-Python을 활용한 범용 디버깅 자동화 프레임워크입니다. Windows 실행 파일(EXE, DLL) 수준에서 함수 후킹, 메모리 읽기/쓰기, 로그 수집, 조건부 패치 적용 등의 기능을 제공합니다.

## 주요 기능

- **함수 후킹 및 동적 삽입:** Win32 API 함수를 후킹하여 호출 추적 및 조작
- **호출 인자 및 리턴값 로깅:** 함수 호출 인자와 반환값을 자동으로 로깅
- **인자/리턴값 조작:** 특정 조건에 따라 함수 동작을 변경
- **메모리 읽기/쓰기:** 프로세스 메모리 접근 및 수정
- **모듈 정보 조회:** 로드된 모듈 목록 및 주소 정보 조회
- **GUI 요소 핸들러 탐지:** 실행 중인 프로그램의 버튼, 입력 필드, 라벨 등 GUI 요소의 동작 함수 탐지

## 설치 요구사항

- Python 3.6 이상
- frida 패키지
- frida-tools 패키지 (옵션)

```bash
pip install frida frida-tools
```

## 프로젝트 구조

```
a64dbg/
├── main.py              # 프로그램 진입점: 인자 파싱 및 프레임워크 실행
├── controller.py        # Frida 세션 관리 및 후킹 스크립트 로드/메시지 처리
├── memory_utils.py      # 메모리 조작을 위한 유틸리티 함수
├── gui_utils.py         # GUI 요소 탐지 및 분석을 위한 유틸리티 함수
├── examples/            # 예제 스크립트 디렉터리
│   └── detect_gui_handlers.py  # GUI 요소 핸들러 탐지 예제
└── hooks/               # 후킹 스크립트 모듈 디렉터리
    ├── __init__.py
    ├── file_hook.py     # CreateFileW 등 파일 관련 API 후킹
    ├── messagebox_hook.py  # MessageBoxW 등 UI 관련 API 후킹
    ├── memory_hook.py   # 메모리 조작 관련 기능
    ├── registry_hook.py # 레지스트리 API 후킹
    └── gui_element_hook.py # GUI 요소 핸들러 탐지 기능
```

## 사용 방법

### 1. 실행 중인 프로세스에 연결

```bash
python main.py <프로세스이름 또는 PID>
```

예시:
```bash
python main.py notepad.exe
```

### 2. 새 프로세스 생성 및 연결

```bash
python main.py --spawn <실행파일경로>
```

예시:
```bash
python main.py --spawn "C:\Windows\System32\notepad.exe"
```

## 후킹 예제

### 1. 파일 접근 모니터링 및 제어

a64dbg는 `CreateFileW` 함수를 후킹하여 파일 접근을 모니터링하고 제어합니다:

- 모든 파일 접근 로그 자동 기록
- `.tmp` 확장자를 가진 파일 접근 시 다른 파일로 리다이렉션
- `notallowed` 문자열이 포함된 파일명에 대한 접근 차단

### 2. 메시지 박스 모니터링 및 수정

`MessageBoxW` 함수를 후킹하여:

- 메시지 박스 내용 및 제목 로깅
- 메시지에 `secret` 단어가 포함된 경우 텍스트 변경
- 사용자 응답 버튼 로깅

### 3. 레지스트리 액세스 모니터링

`RegOpenKeyExW`와 `RegQueryValueExW` 함수를 후킹하여:

- 레지스트리 키 접근 로깅
- 값 조회 작업 추적
- 레지스트리 키 값 및 타입 분석

### 4. GUI 요소 핸들러 탐지

GUI 요소 핸들러 탐지 기능은 Windows 애플리케이션의 버튼, 메뉴, 입력 필드 등의 사용자 인터페이스 요소가 어떤 함수를 호출하는지 탐지합니다:

- 실행 중인 프로그램의 모든 윈도우 및 컨트롤 스캔
- 사용자의 버튼 클릭, 메뉴 선택 등의 작업 시 호출되는 핸들러 함수 탐지
- 컨트롤 ID, 텍스트, 클래스 등 세부 정보 제공
- 핸들러 함수 주소와 호출 스택 기록
- 탐지된 핸들러 목록을 파일로 저장 가능

예시:
```python
from controller import FridaController
from gui_utils import GuiElementUtils

# Frida 세션 및 GUI 유틸리티 초기화
controller = FridaController("target.exe")
gui_utils = GuiElementUtils(controller.script)

# 모든 윈도우 스캔
gui_utils.scan_all_windows()

# 특정 윈도우의 컨트롤 정보 가져오기
gui_utils.get_window_info("0x00A1B2C3")

# 윈도우 모니터링 시작 (버튼 클릭 등 동작 탐지)
gui_utils.monitor_window("0x00A1B2C3")

# 사용자에게 상호작용 요청 및 핸들러 탐지 대기
handlers = gui_utils.wait_for_handler(timeout=30)

# 탐지된 핸들러 출력
gui_utils.print_handlers()
```

예제 실행:
```bash
python examples/detect_gui_handlers.py notepad.exe
```

## 메모리 유틸리티 사용법

```python
from controller import FridaController
from memory_utils import MemoryUtils

# Frida 세션 생성
controller = FridaController("notepad.exe")
controller.run()

# 메모리 유틸리티 초기화
memory_utils = MemoryUtils(controller.script)

# 모듈 목록 조회
memory_utils.enumerate_modules()

# 특정 모듈의 함수 목록 조회
memory_utils.enumerate_exports("kernel32.dll")

# 메모리 덤프
memory_utils.dump_memory(0x12345678, 128)

# 메모리 쓰기 (코드 패치)
memory_utils.write_memory(0x12345678, [0x90, 0x90, 0x90])  # NOP 명령어로 패치
```

## 새 후킹 모듈 추가 방법

1. `hooks` 디렉토리 내에 새 Python 파일 생성 (예: `network_hook.py`)
2. `hook_script` 문자열 변수에 JavaScript 코드 작성
3. 특별한 등록 과정 없이 자동으로 로드됨

## 라이센스

이 프로젝트는 MIT 라이센스 하에 배포됩니다. 