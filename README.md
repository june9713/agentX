# AgentX - Web Automation and Analysis Tool

AgentX is a powerful web automation and analysis tool that leverages Chrome DevTools Protocol (CDP) to interact with web pages, analyze their structure, and automate various tasks. It's particularly useful for web scraping, automated testing, and real-time web interaction.

## Features

- Chrome DevTools Protocol (CDP) integration
- Real-time web page analysis and crawling
- JavaScript code extraction and analysis
- Automated browser control and window management
- Screenshot capture and image processing
- WebSocket-based communication
- Comprehensive logging system

## Prerequisites

- Python 3.8 or higher
- Chrome or Slimjet browser
- Windows operating system (for window management features)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/agentX.git
cd agentX
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
.\venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Project Structure

```
agentX/
├── src/                    # Main source code directory
│   ├── crawlers/          # Crawling-related code
│   ├── js/                # JavaScript-related code
│   ├── mcp/               # MCP-related code
│   └── agents/            # Agent-related code
├── tests/                 # Test code
├── docs/                  # Documentation
├── examples/              # Example code
├── config/                # Configuration files
└── logs/                  # Log files
```

## Usage

### Basic Usage with test1.py

The `test1.py` script demonstrates basic usage of the ChromeCDPClient for web page analysis:

```python
from agents.chatgpt.chrome_cdp_client import ChromeCDPClient

# Initialize the client
ccc = ChromeCDPClient(
    browser_path="C:\Program Files\Slimjet\slimjet.exe",
    profile_name="Default",
    position=(0, 0),
    size=(1024, 768),
    pythonpath="./Scripts/python.exe"
)

# Analyze a webpage
ccc.analisys_crawl_page(
    ccc.browser,
    "https://translate.google.co.kr/?sl=en&tl=ko&op=translate",
    "Please crawl how Google Translate processes voice in real-time",
    "https://translate.google.co.kr/?sl=en&tl=ko&op=translate"
)
```

### Interactive Command Session with test2.py

The `test2.py` script demonstrates how to use the interactive command session feature:

```python
from agents.chatgpt.chrome_cdp_client import ChromeCDPClient

# Initialize the client
ccc = ChromeCDPClient(
    browser_path="C:\Program Files\Slimjet\slimjet.exe",
    profile_name="Default",
    position=(0, 0),
    size=(1024, 768),
    pythonpath="./Scripts/python.exe"
)

# Start interactive command session
ccc.cmd_session_main()
```

The command session provides an interactive interface where you can:
- Enter commands to be executed
- Get real-time feedback on command execution
- Type 'exit' to end the session
- View detailed error messages if commands fail

Example commands you can try:
- "Show me the current page structure"
- "Extract all JavaScript code from this page"
- "Analyze the page for dynamic content"
- "Take a screenshot of the current view"

### Key Components

1. **ChromeCDPClient**: Main class for browser interaction
   - Window management
   - Screenshot capture
   - Page analysis
   - JavaScript extraction

2. **Browser Control**
   - Start/stop browser
   - Tab management
   - Page navigation
   - Element interaction

3. **Analysis Features**
   - HTML source analysis
   - JavaScript code extraction
   - Real-time page monitoring
   - Automated testing

## Configuration

The tool can be configured through various parameters:

- `browser_path`: Path to the browser executable
- `profile_name`: Browser profile to use
- `position`: Window position (x, y)
- `size`: Window size (width, height)
- `pythonpath`: Path to Python executable

## Logging

Logs are stored in the `logs` directory:
- `myagent.log`: Main application log
- Debug logs for specific operations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Chrome DevTools Protocol
- PyChrome library
- OpenCV for image processing 