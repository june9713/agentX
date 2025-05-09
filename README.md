# AgentX - LLM-Powered Browser Automation Agent 🤖

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Stars](https://img.shields.io/github/stars/yourusername/agentX?style=social)](https://github.com/yourusername/agentX)

> Transform your browser into an intelligent agent powered by Large Language Models (LLMs) 🚀

## 🌟 Why AgentX?

AgentX revolutionizes browser automation by combining the power of Large Language Models with Chrome DevTools Protocol. Unlike traditional automation tools, AgentX understands natural language commands and can perform complex web interactions with human-like intelligence.

### Key Advantages

- 🤖 **LLM-Powered Intelligence**: Natural language understanding for complex tasks
- 🔄 **Real-time Interaction**: Dynamic web page analysis and response
- 🧠 **Contextual Awareness**: Maintains conversation context for better task execution
- 🛠️ **Extensible Architecture**: Easy to integrate with various LLM providers
- 📊 **Comprehensive Analysis**: Deep insights into web page structure and behavior

## ✨ Features

### 1. Intelligent Browser Control
- Natural language command processing
- Context-aware web navigation
- Dynamic element interaction
- Smart form filling and submission

### 2. Advanced Web Analysis
- Real-time page structure analysis
- JavaScript code extraction and understanding
- Dynamic content detection
- Automated testing capabilities

### 3. LLM Integration
- ChatGPT-powered command interpretation
- Intelligent task planning
- Natural language response generation
- Contextual error handling

### 4. Developer Tools
- Comprehensive logging system
- Debug mode for development
- Performance optimization
- Error tracking and reporting

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Chrome or Slimjet browser
- Windows operating system
- OpenAI API key (for ChatGPT integration)

### Installation

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

4. Configure your environment:
```bash
cp .env.example .env
# Edit .env with your API keys and settings
```

## 💡 Usage Examples

### 1. Basic Web Analysis

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

# Analyze a webpage with natural language
ccc.analisys_crawl_page(
    ccc.browser,
    "https://translate.google.co.kr/?sl=en&tl=ko&op=translate",
    "Please analyze how Google Translate processes voice in real-time",
    "https://translate.google.co.kr/?sl=en&tl=ko&op=translate"
)
```

### 2. Interactive Command Session

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

Try these example commands:
- "Analyze the current page structure and identify dynamic elements"
- "Extract all JavaScript code and explain its functionality"
- "Monitor network requests and identify API endpoints"
- "Take a screenshot and analyze the visual elements"

## 🏗️ Architecture

### Core Components

1. **LLM Integration Layer**
   - Natural language processing
   - Command interpretation
   - Response generation
   - Context management

2. **Browser Control Layer**
   - Chrome DevTools Protocol integration
   - Window management
   - Tab control
   - Page interaction

3. **Analysis Engine**
   - HTML parsing
   - JavaScript analysis
   - Network monitoring
   - Performance tracking

4. **Task Execution Engine**
   - Command queue management
   - Error handling
   - State management
   - Result processing

## 🔧 Configuration

### Environment Variables
```env
OPENAI_API_KEY=your_api_key
BROWSER_PATH=path_to_browser
DEFAULT_PROFILE=profile_name
LOG_LEVEL=INFO
```

### Browser Settings
- Window position and size
- Profile selection
- Performance options
- Debug mode

## 📊 Performance

AgentX is optimized for:
- Fast response times
- Low memory usage
- Efficient resource management
- Reliable task execution

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📝 License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0) with additional attribution requirements.

### Key License Terms

1. **Commercial Use**
   - Commercial use is permitted but requires prior notification to the original author
   - Must include project details, use case, and timeline
   - Attribution must be prominently displayed

2. **Attribution Requirements**
   - Original author's name and repository link must be displayed
   - License information must be included in documentation and UI
   - Source code headers must contain attribution

3. **Modifications**
   - Modifications must be clearly marked
   - Modified versions must include change log
   - Original license and attribution requirements must be preserved

4. **Distribution**
   - All distributions must include original LICENSE file
   - Additional attribution requirements must be included
   - Original copyright notice must be preserved

For detailed license terms and commercial use inquiries, please see the [LICENSE](LICENSE) file or contact the author.

## 🙏 Acknowledgments

- [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [OpenAI](https://openai.com/) for ChatGPT API
- [PyChrome](https://github.com/fate0/pychrome) library
- [OpenCV](https://opencv.org/) for image processing

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/agentX&type=Date)](https://star-history.com/#yourusername/agentX&Date)

## 📞 Support

- [GitHub Issues](https://github.com/yourusername/agentX/issues)
- [Discord Community](https://discord.gg/yourdiscord)
- [Documentation](https://docs.agentx.dev)

---

Made with ❤️ by [Your Name](https://github.com/yourusername)

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/yourusername) 