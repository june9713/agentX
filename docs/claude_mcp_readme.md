# Claude MCP 설정 가이드

이 가이드는 데스크탑에서 MCP 서버를 테스트하기 위한 Claude MCP 설정을 설명합니다.

## 시작하기 전에

테스트를 하기 전에 다음 조건이 필요합니다:

1. Python 3.8 이상이 설치되어 있어야 합니다.
2. 필요한 패키지가 설치되어 있어야 합니다:
   ```
   pip install websockets==11.0.3 aiohttp==3.9.1 pydantic==2.5.2
   ```
3. Chrome 핸들러 테스트를 위해서는 Chrome이 원격 디버깅 모드로 실행되어 있어야 합니다.

## MCP 서버 실행하기

1. 다음 명령어로 MCP 서버를 실행합니다:

   ```bash
   python src/mcp_server.py
   ```

2. 서버가 실행되면 다음과 같은 메시지가 표시됩니다:
   ```
   MCP Server started on localhost:8765
   Available handlers: chrome, excel
   ```

## Claude MCP 설정 파일

`claude_mcp_config.json` 파일을 생성하여 다음 설정을 포함시킵니다:

```json
{
  "server": {
    "url": "ws://localhost:8765",
    "connection_timeout": 5000,
    "reconnect_attempts": 3,
    "reconnect_delay": 1000
  },
  "handlers": {
    "chrome": {
      "enabled": true,
      "connection": {
        "url": "http://localhost:9333",
        "debug": false
      }
    },
    "excel": {
      "enabled": true,
      "connection": {
        "create_new_workbook": true
      }
    }
  },
  "logging": {
    "level": "info",
    "file": "claude_mcp.log",
    "console": true
  },
  "security": {
    "verify_ssl": false,
    "require_authentication": false
  },
  "commands": {
    "chrome": {
      "navigate": {
        "url": "https://claude.ai"
      },
      "eval": {
        "return_by_value": true
      },
      "screenshot": {
        "format": "png",
        "quality": 100
      }
    },
    "excel": {
      "default_sheet": "Sheet1"
    }
  },
  "session": {
    "auto_connect": true,
    "timeout": 300000,
    "keep_alive": true
  },
  "advanced": {
    "message_size_limit": 10485760,
    "debug_mode": false,
    "performance_metrics": false
  }
}
```

## Chrome 핸들러 테스트를 위한 설정

Chrome 핸들러를 테스트하기 위해서는 Chrome을 원격 디버깅 모드로 실행해야 합니다:

### Windows:

```
"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9333
```

### macOS:

```
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9333
```

### Linux:

```
google-chrome --remote-debugging-port=9333
```

## 메시지 형식

MCP 서버와 통신하는 데 사용되는 기본 메시지 형식은 다음과 같습니다:

### 요청 메시지

```json
{
  "type": "request",
  "target": "핸들러_이름",
  "command": "명령어",
  "params": {
    "파라미터1": "값1",
    "파라미터2": "값2"
  },
  "id": "요청_ID"
}
```

### 응답 메시지

```json
{
  "id": "요청_ID",
  "success": true/false,
  "result": {
    "결과_데이터"
  },
  "error": "오류_메시지(실패 시)"
}
```

## 사용 가능한 핸들러 및 명령어

### 서버 핸들러

- `list_handlers`: 사용 가능한 모든 핸들러 목록을 반환합니다.
- `has_handler`: 특정 핸들러가 사용 가능한지 확인합니다.

### Chrome 핸들러

- `connect`: Chrome에 연결합니다.
- `disconnect`: Chrome 연결을 종료합니다.
- `navigate`: 지정된 URL로 페이지를 이동합니다.
- `reload`: 현재 페이지를 새로고침합니다.
- `eval`: JavaScript 코드를 실행합니다.
- `screenshot`: 현재 페이지의 스크린샷을 캡처합니다.
- `get_document`: DOM 문서를 가져옵니다.

### Excel 핸들러

- `connect`: Excel에 연결합니다.
- `disconnect`: Excel 연결을 종료합니다.
- `get_worksheets`: 워크시트 목록을 가져옵니다.
- `read_cell`: 셀 값을 읽습니다.
- `write_cell`: 셀에 값을 씁니다.

## 테스트 실행하기

테스트 스크립트를 실행하여 MCP 서버와 핸들러를 테스트할 수 있습니다:

```bash
python src/test_mcp.py
```

이 스크립트는 다음을 수행합니다:
1. 서버 연결 테스트
2. Chrome 핸들러 테스트 (페이지 이동, JavaScript 실행, 스크린샷 캡처)
3. Excel 핸들러 테스트 (워크시트 목록 가져오기, 셀 값 읽기)

## 문제 해결

1. **연결 오류**
   - MCP 서버가 실행 중인지 확인하세요.
   - 방화벽 설정이 WebSocket 연결을 차단하고 있지 않은지 확인하세요.

2. **Chrome 핸들러 오류**
   - Chrome이 원격 디버깅 모드로 실행 중인지 확인하세요.
   - 포트 9333가 다른 프로세스에 의해 사용되고 있지 않은지 확인하세요.

3. **Excel 핸들러 오류**
   - Excel이 설치되어 있고 사용 가능한지 확인하세요.
   - 현재는 Excel 핸들러는 실제 구현이 완료되지 않은 상태이므로 실제 Excel과의 상호 작용은 제한적입니다. 