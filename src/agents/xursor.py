#!/usr/bin/env python3
# xursor.py - A custom implementation of Cursor AI with agent mode capabilities

import json
import os
import time
import argparse
import sys
import re
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
import requests
from dataclasses import dataclass, field
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('xursor')

# Model-related constants
DEFAULT_MODEL = "claude-3-opus-20240229"
AVAILABLE_MODELS = ["claude-3-opus-20240229", "claude-3-sonnet-20240229", "gpt-4-turbo"]

@dataclass
class ToolCall:
    name: str
    parameters: Dict[str, Any]
    result: Optional[Any] = None
    error: Optional[str] = None

@dataclass
class AgentState:
    conversation_history: List[Dict[str, Any]] = field(default_factory=list)
    tool_calls: List[ToolCall] = field(default_factory=list)
    workspace_path: str = ""
    current_file: Optional[str] = None
    current_line: int = 0
    
class Tool:
    def __init__(self, name: str, description: str, handler: Callable):
        self.name = name
        self.description = description
        self.handler = handler
        
    def execute(self, parameters: Dict[str, Any]) -> Any:
        return self.handler(parameters)

class XursorAgent:
    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, workspace_path: str = None):
        self.api_key = api_key
        self.model = model
        self.state = AgentState()
        self.tools = {}
        
        # Set workspace path to current directory if not provided
        self.state.workspace_path = workspace_path or os.getcwd()
        
        # Register built-in tools
        self._register_default_tools()
        
    def _register_default_tools(self):
        """Register the default set of tools available to the agent."""
        self.register_tool(
            "codebase_search",
            "Find snippets of code from the codebase most relevant to the search query",
            self._handle_codebase_search
        )
        self.register_tool(
            "read_file",
            "Read the contents of a file",
            self._handle_read_file
        )
        self.register_tool(
            "run_terminal_cmd",
            "Run a terminal command",
            self._handle_run_terminal_cmd
        )
        self.register_tool(
            "list_dir",
            "List the contents of a directory",
            self._handle_list_dir
        )
        self.register_tool(
            "grep_search",
            "Search for patterns in files",
            self._handle_grep_search
        )
        self.register_tool(
            "edit_file",
            "Edit an existing file or create a new file",
            self._handle_edit_file
        )
        self.register_tool(
            "file_search",
            "Search for files by name",
            self._handle_file_search
        )
        
    def register_tool(self, name: str, description: str, handler: Callable):
        """Register a new tool that the agent can use."""
        self.tools[name] = Tool(name, description, handler)
        
    def _handle_codebase_search(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Perform semantic search over codebase."""
        query = parameters.get("query", "")
        target_dirs = parameters.get("target_directories", [])
        
        # Simplified implementation - in a real implementation, this would use
        # vector embeddings and semantic search
        results = []
        search_dirs = target_dirs if target_dirs else [self.state.workspace_path]
        
        for directory in search_dirs:
            for root, _, files in os.walk(os.path.join(self.state.workspace_path, directory)):
                for file in files:
                    if file.endswith(('.py', '.js', '.ts', '.jsx', '.tsx', '.html', '.css')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                if query.lower() in content.lower():
                                    # Simple keyword match as placeholder for semantic search
                                    relative_path = os.path.relpath(file_path, self.state.workspace_path)
                                    results.append({
                                        "file": relative_path,
                                        "snippet": content[:200] + "..." if len(content) > 200 else content,
                                        "score": 0.85  # Dummy score
                                    })
                        except Exception as e:
                            logger.error(f"Error reading file {file_path}: {e}")
        
        return {
            "results": results[:5],  # Return top 5 results
            "explanation": f"Found {len(results)} files matching query: {query}"
        }
        
    def _handle_read_file(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Read contents of a file."""
        target_file = parameters.get("target_file")
        offset = parameters.get("offset", 0)
        limit = parameters.get("limit", 200)
        read_entire = parameters.get("should_read_entire_file", False)
        
        if not target_file:
            return {"error": "No target file specified"}
            
        # Resolve file path
        if os.path.isabs(target_file):
            file_path = target_file
        else:
            file_path = os.path.join(self.state.workspace_path, target_file)
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
                if read_entire:
                    content = ''.join(lines)
                    return {
                        "content": content,
                        "file_path": file_path,
                        "total_lines": len(lines)
                    }
                else:
                    # Cap lines to actual file length
                    offset = max(0, min(offset, len(lines) - 1))
                    end = min(offset + limit, len(lines))
                    
                    # Extract the requested portion
                    selected_lines = lines[offset:end]
                    content = ''.join(selected_lines)
                    
                    return {
                        "content": content,
                        "file_path": file_path,
                        "start_line": offset + 1,  # Convert to 1-indexed
                        "end_line": end,
                        "total_lines": len(lines)
                    }
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return {"error": f"Could not read file: {str(e)}"}
            
    def _handle_run_terminal_cmd(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Run a shell command in the workspace."""
        command = parameters.get("command", "")
        is_background = parameters.get("is_background", False)
        
        if not command:
            return {"error": "No command specified"}
            
        try:
            # For safety in a real implementation, you would want to sanitize 
            # and restrict commands that can be run
            if is_background:
                # Run command in background
                cmd = f"{command} &"
                process = os.popen(cmd)
                output = "Command running in background"
            else:
                process = os.popen(command)
                output = process.read()
                
            return {
                "command": command,
                "output": output,
                "exit_code": process.close() or 0
            }
        except Exception as e:
            logger.error(f"Error running command {command}: {e}")
            return {"error": f"Failed to run command: {str(e)}"}
            
    def _handle_list_dir(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """List contents of a directory."""
        rel_path = parameters.get("relative_workspace_path", "")
        dir_path = os.path.join(self.state.workspace_path, rel_path)
        
        try:
            items = os.listdir(dir_path)
            result = []
            
            for item in items:
                item_path = os.path.join(dir_path, item)
                is_dir = os.path.isdir(item_path)
                
                result.append({
                    "name": item,
                    "is_directory": is_dir,
                    "size": os.path.getsize(item_path) if not is_dir else None
                })
                
            return {
                "path": rel_path,
                "items": result
            }
        except Exception as e:
            logger.error(f"Error listing directory {dir_path}: {e}")
            return {"error": f"Failed to list directory: {str(e)}"}
            
    def _handle_grep_search(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Search for patterns in files."""
        query = parameters.get("query", "")
        case_sensitive = parameters.get("case_sensitive", False)
        include_pattern = parameters.get("include_pattern", "")
        exclude_pattern = parameters.get("exclude_pattern", "")
        
        if not query:
            return {"error": "No search query specified"}
            
        # Simple regex-based search implementation
        results = []
        
        for root, _, files in os.walk(self.state.workspace_path):
            for file in files:
                # Apply include/exclude patterns
                if include_pattern and not self._matches_glob(file, include_pattern):
                    continue
                if exclude_pattern and self._matches_glob(file, exclude_pattern):
                    continue
                    
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for i, line in enumerate(f):
                            flags = 0 if case_sensitive else re.IGNORECASE
                            if re.search(query, line, flags=flags):
                                rel_path = os.path.relpath(file_path, self.state.workspace_path)
                                results.append({
                                    "file": rel_path,
                                    "line_number": i + 1,
                                    "line": line.rstrip()
                                })
                                
                                # Cap results
                                if len(results) >= 50:
                                    break
                except Exception as e:
                    logger.debug(f"Could not search file {file_path}: {e}")
                    
                # Cap results
                if len(results) >= 50:
                    break
                    
        return {
            "matches": results,
            "total_matches": len(results),
            "truncated": len(results) >= 50
        }
        
    def _matches_glob(self, filename: str, pattern: str) -> bool:
        """Simple glob pattern matching."""
        import fnmatch
        return fnmatch.fnmatch(filename, pattern)
        
    def _handle_edit_file(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Edit existing file or create a new one."""
        target_file = parameters.get("target_file", "")
        code_edit = parameters.get("code_edit", "")
        instructions = parameters.get("instructions", "")
        
        if not target_file:
            return {"error": "No target file specified"}
            
        # Resolve file path
        if os.path.isabs(target_file):
            file_path = target_file
        else:
            file_path = os.path.join(self.state.workspace_path, target_file)
            
        try:
            # Check if we're creating a new file
            creating_new = not os.path.exists(file_path)
            
            if creating_new:
                # Create a new file with the provided content
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(code_edit)
                    
                return {
                    "file_path": file_path,
                    "action": "created",
                    "success": True
                }
            else:
                # Edit existing file
                with open(file_path, 'r', encoding='utf-8') as f:
                    current_content = f.read()
                
                # Apply edits - in a real implementation, this would parse the special
                # comments like "// ... existing code ..." and apply the changes accordingly
                # This is a simplified implementation that just replaces the file
                if "// ... existing code ..." in code_edit:
                    # Simple placeholder implementation - in reality this would be a more
                    # sophisticated diff/patch algorithm
                    logger.info("Detected edit markers, would apply partial edits in real implementation")
                    
                    # For demo purposes, just replace the file
                    new_content = code_edit.replace("// ... existing code ...", 
                                                  "# This would preserve existing code in a real implementation")
                else:
                    new_content = code_edit
                    
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                    
                return {
                    "file_path": file_path,
                    "action": "edited",
                    "success": True
                }
        except Exception as e:
            logger.error(f"Error editing file {file_path}: {e}")
            return {"error": f"Failed to edit file: {str(e)}"}
    
    def _handle_file_search(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Search for files by name."""
        query = parameters.get("query", "")
        
        if not query:
            return {"error": "No search query specified"}
            
        results = []
        for root, _, files in os.walk(self.state.workspace_path):
            for file in files:
                if query.lower() in file.lower():
                    rel_path = os.path.relpath(os.path.join(root, file), self.state.workspace_path)
                    results.append(rel_path)
                    
                    # Cap results
                    if len(results) >= 10:
                        break
                        
            if len(results) >= 10:
                break
                
        return {
            "files": results,
            "total_matches": len(results),
            "truncated": len(results) >= 10
        }
        
    def _prepare_messages(self, user_query: str) -> List[Dict[str, Any]]:
        """Prepare the messages for the LLM API call."""
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a powerful agentic AI coding assistant called Xursor. "
                    "You help users with coding tasks by using various tools to navigate, "
                    "search, and modify code in their workspace. You should be concise and direct "
                    "in your communication. You can use tools to complete tasks when needed."
                )
            }
        ]
        
        # Add conversation history
        for message in self.state.conversation_history:
            messages.append(message)
            
        # Create a prompt with additional context
        context = {
            "workspace_path": self.state.workspace_path,
            "current_file": self.state.current_file,
            "current_line": self.state.current_line
        }
        
        additional_context = json.dumps(context, indent=2)
        
        prompt = f"""
<additional_data>
{additional_context}
</additional_data>

<user_query>
{user_query}
</user_query>
"""
        
        messages.append({
            "role": "user",
            "content": prompt
        })
        
        return messages
        
    def _call_llm_api(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Call LLM API with the given messages.
        
        This is a placeholder for actual API calls to Claude, GPT-4, etc.
        In a real implementation, this would make HTTP requests to the API.
        """
        # Simulate API response with placeholder
        logger.info(f"Would call {self.model} API with {len(messages)} messages")
        
        # In a real implementation, this would make an API call and get the response
        # This is a placeholder response structure
        return {
            "id": f"chatcmpl-{int(time.time()*1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": self.model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "I'll help you with that coding task! Let me check the files in your workspace.",
                        "tool_calls": [
                            {
                                "id": f"call_{int(time.time()*1000)}",
                                "type": "function",
                                "function": {
                                    "name": "list_dir",
                                    "arguments": json.dumps({"relative_workspace_path": ""})
                                }
                            }
                        ]
                    },
                    "finish_reason": "tool_calls"
                }
            ]
        }
    
    def _extract_tool_calls(self, response: Dict[str, Any]) -> List[ToolCall]:
        """Extract tool calls from the LLM response."""
        tool_calls = []
        
        try:
            choice = response["choices"][0]
            message = choice["message"]
            
            if "tool_calls" in message:
                for tool_call in message["tool_calls"]:
                    if tool_call["type"] == "function":
                        function = tool_call["function"]
                        name = function["name"]
                        parameters = json.loads(function["arguments"])
                        
                        tool_calls.append(ToolCall(name=name, parameters=parameters))
        except Exception as e:
            logger.error(f"Error extracting tool calls: {e}")
            
        return tool_calls
        
    def _execute_tool_calls(self, tool_calls: List[ToolCall]) -> None:
        """Execute the tool calls and store results."""
        for tool_call in tool_calls:
            if tool_call.name in self.tools:
                try:
                    result = self.tools[tool_call.name].execute(tool_call.parameters)
                    tool_call.result = result
                except Exception as e:
                    logger.error(f"Error executing tool {tool_call.name}: {e}")
                    tool_call.error = str(e)
            else:
                tool_call.error = f"Unknown tool: {tool_call.name}"
                
        # Add to state
        self.state.tool_calls.extend(tool_calls)
        
    def execute(self, user_query: str, max_steps: int = 10) -> Dict[str, Any]:
        """Execute the agent with the given user query."""
        # Add user message to history
        self.state.conversation_history.append({"role": "user", "content": user_query})
        
        steps_taken = 0
        last_assistant_message = None
        
        while steps_taken < max_steps:
            # Prepare messages for LLM
            messages = self._prepare_messages(user_query)
            
            # Call LLM API
            response = self._call_llm_api(messages)
            
            # Extract assistant message
            assistant_message = response["choices"][0]["message"]
            last_assistant_message = assistant_message["content"]
            
            # Add to conversation history
            self.state.conversation_history.append({"role": "assistant", "content": last_assistant_message})
            
            # Check if we need to execute tool calls
            finish_reason = response["choices"][0]["finish_reason"]
            
            if finish_reason == "tool_calls":
                # Extract and execute tool calls
                tool_calls = self._extract_tool_calls(response)
                self._execute_tool_calls(tool_calls)
                
                # Add tool results to conversation
                for tool_call in tool_calls:
                    tool_message = {
                        "tool_call_id": f"call_{int(time.time()*1000)}",
                        "role": "tool",
                        "name": tool_call.name,
                        "content": json.dumps(tool_call.result if tool_call.result else {"error": tool_call.error})
                    }
                    self.state.conversation_history.append(tool_message)
            else:
                # No more tool calls, we're done
                break
                
            steps_taken += 1
            
        return {
            "response": last_assistant_message,
            "steps_taken": steps_taken,
            "tool_calls": [
                {"name": tc.name, "parameters": tc.parameters, "result": tc.result, "error": tc.error}
                for tc in self.state.tool_calls
            ]
        }

def main():
    """CLI entry point for xursor."""
    parser = argparse.ArgumentParser(description="Xursor - A custom Cursor AI implementation with agent capabilities")
    parser.add_argument("--api-key", help="API key for LLM service", default=os.environ.get("XURSOR_API_KEY"))
    parser.add_argument("--model", help="Model to use", choices=AVAILABLE_MODELS, default=DEFAULT_MODEL)
    parser.add_argument("--workspace", help="Workspace path (defaults to current directory)", default=os.getcwd())
    parser.add_argument("query", nargs="?", help="Query to process (if not provided, enters interactive mode)")
    
    args = parser.parse_args()
    
    if not args.api_key:
        print("Error: API key not provided. Use --api-key or set XURSOR_API_KEY environment variable.")
        sys.exit(1)
        
    agent = XursorAgent(api_key=args.api_key, model=args.model, workspace_path=args.workspace)
    
    if args.query:
        # Process a single query
        result = agent.execute(args.query)
        print(result["response"])
    else:
        # Interactive mode
        print(f"Xursor Agent initialized with model {args.model}")
        print(f"Workspace: {args.workspace}")
        print("Enter your queries (Ctrl+C to exit):")
        
        try:
            while True:
                query = input("> ")
                if query.lower() in ("exit", "quit"):
                    break
                    
                result = agent.execute(query)
                print(result["response"])
        except KeyboardInterrupt:
            print("\nExiting Xursor")
            
if __name__ == "__main__":
    main()
