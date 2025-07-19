#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import json
import logging
import readline
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.logging import RichHandler
from rich.markdown import Markdown
import re # Added for robust regex parsing of tool output
import io # Crucial fix for StringIO
import shlex # CRITICAL FIX: For shell quoting

# ========== Global Configuration ==========
# --- API and Model ---
API_KEY = os.environ.get("TOGETHER_API_KEY")
MODEL = "mistralai/Mixtral-8x7B-Instruct-v0.1"
API_URL = "https://api.together.xyz/v1/chat/completions"

# --- Rich Console ---
console = Console()

# --- Logging Setup ---
logging.basicConfig(
    level="INFO",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("shellgpt_pro.log", mode='w'),
        RichHandler(console=console, rich_tracebacks=True, show_path=False)
    ]
)
log = logging.getLogger("ShellGPT-Pro")

# --- Conversation History ---
conversation_history = []

# ========== Core Features / "Plugins" ==========

class CommandRegistry:
    """A registry for discoverable and executable commands."""
    def __init__(self):
        self.commands = {}

    def register(self, name):
        def decorator(cls):
            self.commands[name] = cls()
            log.info(f"Registered command: {name}")
            return cls
        return decorator

    def get_command(self, name):
        return self.commands.get(name)

    def get_command_docs(self):
        return {name: cmd.__doc__ for name, cmd in self.commands.items()}

cmd_registry = CommandRegistry()

def _run_shell_command(command_str, check_return_code=True):
    """
    A helper function to safely run shell commands.
    If check_return_code is False, it will return stdout/stderr even on non-zero exit.
    """
    try:
        # Use text=True for Python 3.7+ to automatically decode stdout/stderr
        # stderr is redirected to stdout for easier capture of all command output/errors
        result = subprocess.run(
            command_str,
            shell=True,
            capture_output=True,
            text=True,
            check=check_return_code, # Raise CalledProcessError if non-zero exit code
            timeout=30 # Add a timeout for safety
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        log.error(f"Shell command '{command_str}' failed with exit code {e.returncode}:\n{e.stdout.strip()}")
        return f"Error executing command (Exit Code {e.returncode}):\n{e.stdout.strip()}"
    except subprocess.TimeoutExpired:
        log.error(f"Shell command '{command_str}' timed out after 30 seconds.")
        return f"Error: Command timed out after 30 seconds."
    except Exception as e:
        log.error(f"An unexpected error occurred while running shell command '{command_str}': {e}", exc_info=True)
        return f"An unexpected error occurred: {e}"

# --- Internet Commands ---

@cmd_registry.register("search_web")
class WebSearchCommand:
    """Performs a web search and returns results (titles and URLs). Usage: search_web <query>"""
    def run(self, query):
        if not query:
            return "Error: search_web requires a query."
        log.info(f"Performing web search for: {query}")
        try:
            # Using DuckDuckGo for a simple example as it's less aggressive on scraping
            # Note: For production, use a dedicated search API (e.g., Google Custom Search API, SerpApi)
            search_url = f"https://duckduckgo.com/html/?q={requests.utils.quote(query)}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
            response = requests.get(search_url, headers=headers, timeout=10)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            results = []
            
            for link in soup.find_all('a', class_='result__a'):
                title = link.get_text(strip=True)
                url = link.get('href')
                if title and url and url.startswith('http'): # Filter out non-http links
                    results.append({"title": title, "url": url})
            
            if results:
                # Limit to top 5-10 results to not overload AI context
                return json.dumps(results[:10], indent=2)
            else:
                return "No search results found."

        except requests.exceptions.RequestException as e:
            log.error(f"Network error during web search for '{query}': {e}")
            return f"Error: Network issue during web search. {e}"
        except Exception as e:
            log.error(f"Error during web search for '{query}': {e}", exc_info=True)
            return f"Error: Failed to perform web search due to unexpected issue. {e}"

@cmd_registry.register("scrape_web")
class WebScrapeCommand:
    """Scrapes clean text content from a URL. Usage: scrape_web <url>"""
    def run(self, url):
        if not url:
            return "Error: scrape_web requires a URL."
        try:
            # Clean up URL for consistent requests
            clean_url = url.strip()
            headers = {'User-Agent': 'Mozilla/55.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'}
            response = requests.get(clean_url, headers=headers, timeout=15) # Increased timeout
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Remove script, style, and navigation elements for cleaner text
            for script_or_style in soup(['script', 'style', 'nav', 'header', 'footer', 'aside', 'form']):
                script_or_style.extract()

            # Get text from common content tags
            # Use get_text(separator='\n', strip=True) to preserve some structure
            text_elements = soup.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'code', 'pre', 'blockquote', 'div'])
            text = '\n'.join(element.get_text(separator=' ', strip=True) for element in text_elements if element.get_text(strip=True))
            
            # Further clean up multiple newlines and spaces
            text = re.sub(r'\n\s*\n', '\n\n', text) # Reduce multiple newlines to two
            text = re.sub(r'[ \t]+', ' ', text) # Replace multiple spaces/tabs with single space

            log.info(f"Scraped URL: {clean_url}")
            return text.strip() or f"No significant text content found on the page: {clean_url}."
        except requests.exceptions.RequestException as e:
            log.error(f"Network error scraping {clean_url}: {e}")
            return f"Error: Network issue during web scraping {clean_url}. {e}"
        except Exception as e:
            log.error(f"Error scraping {clean_url}: {e}", exc_info=True)
            return f"Error: Failed to scrape URL {clean_url} due to unexpected issue. {e}"

# --- File System Commands ---

@cmd_registry.register("list_files")
class ListFilesCommand:
    """Lists files in a directory with details. Usage: list_files [path]"""
    def run(self, path="."):
        # CRITICAL FIX: Use shlex.quote for shell arguments
        clean_path = shlex.quote(path.strip()) if path else "."
        return _run_shell_command(f"ls -la {clean_path}")

@cmd_registry.register("read_file")
class ReadFileCommand:
    """Reads the content of a file. Usage: read_file <path>"""
    def run(self, path):
        if not path:
            return "Error: read_file requires a file path."
        try:
            # Strip quotes from the path if they exist, then strip whitespace
            clean_path = path.strip().strip("'\"")
            
            # Ensure path is clean and canonical to prevent directory traversal issues
            absolute_path = os.path.abspath(clean_path)
            
            if not os.path.isfile(absolute_path):
                return f"Error: File not found or is not a regular file: '{clean_path}'"
            
            # Optional: Add security check to prevent reading sensitive areas
            # if not absolute_path.startswith(os.getcwd()):
            #     return f"Error: Reading files outside current directory is restricted: '{clean_path}'"

            with open(absolute_path, 'r', encoding='utf-8') as f:
                content = f.read()
            log.info(f"Read file: {absolute_path}")
            return content
        except Exception as e:
            log.error(f"Error reading file '{clean_path}': {e}", exc_info=True)
            return f"Error reading file: {e}"

@cmd_registry.register("write_file")
class WriteFileCommand:
    """Writes content to a file. Usage: write_file <path> <content>"""
    def run(self, args_str):
        try:
            # The AI needs to put path and content properly.
            # Example: write_file hello.py print("hello world")
            # For simplicity, we assume the path is the first word, and rest is content.
            parts = args_str.split(maxsplit=1)
            if len(parts) < 2:
                return "Error: write_file requires both a file path and content. Format: write_file <path> <content>"
            
            # Strip quotes from the path if they exist, then strip whitespace
            path = parts[0].strip().strip("'\"")
            content = parts[1] # Content can have spaces/newlines
            
            # Ensure path is clean and prevent writing outside current directory for basic safety
            # For a more robust solution, consider explicit permissions or a "safe" directory
            absolute_path = os.path.abspath(path)
            if not absolute_path.startswith(os.getcwd()):
                return f"Error: Cannot write outside the current working directory for security reasons: '{path}'"
            
            # Create parent directories if they don't exist
            os.makedirs(os.path.dirname(absolute_path) or '.', exist_ok=True)

            with open(absolute_path, 'w', encoding='utf-8') as f:
                f.write(content)
            log.info(f"Wrote to file: {absolute_path}")
            return f"Successfully wrote content to '{absolute_path}'."
        except Exception as e:
            log.error(f"Error writing to file '{path}': {e}", exc_info=True)
            return f"Error writing to file: {e}"

@cmd_registry.register("find_files")
class FindFilesCommand:
    """Finds files by name. Usage: find_files <name_pattern> [directory]"""
    def run(self, args_str):
        parts = args_str.split(maxsplit=1)
        if not parts:
            return "Error: find_files requires a name pattern."
        
        name_pattern = parts[0].strip().strip("'\"") # Strip quotes from pattern
        directory = parts[1].strip().strip("'\"") if len(parts) > 1 else "." # Strip quotes from directory

        # CRITICAL FIX: Use shlex.quote for shell arguments
        quoted_name_pattern = shlex.quote(name_pattern)
        quoted_directory = shlex.quote(directory)

        # Using find command, which is generally robust
        return _run_shell_command(f"find {quoted_directory} -name {quoted_name_pattern}")
    
# --- System & Network Commands ---

@cmd_registry.register("shell")
class ShellCommand:
    """Executes a raw shell command. Use with caution. Usage: shell <command>"""
    def run(self, command):
        if not command:
            return "Error: shell requires a command to execute."
        # The _run_shell_command already handles subprocess execution.
        return _run_shell_command(command)

@cmd_registry.register("python")
class PythonExecuteCommand:
    """Executes Python code and captures output. Usage: python <code>"""
    def run(self, code):
        if not code:
            return "Error: python command requires code to execute."
        log.info(f"Executing Python code: {code[:100]}...")
        
        # Redirect stdout to capture print() statements
        old_stdout = sys.stdout
        # CRITICAL FIX: Use io.StringIO for Python 3
        redirected_output = io.StringIO() 
        sys.stdout = redirected_output
        
        try:
            # Using a restricted dictionary for builtins for safety.
            # This is not a complete sandbox, but prevents direct access to os, sys etc.
            # Allowing 'print' specifically for common use cases.
            exec(code, {'__builtins__': {'print': print}}) 
            output = redirected_output.getvalue()
            log.info("Python code executed successfully.")
            return output.strip() or "[No output was printed]"
        except Exception as e:
            log.error(f"Error executing Python code: {e}", exc_info=True)
            return f"Python execution error: {e}"
        finally:
            sys.stdout = old_stdout # Restore original stdout


@cmd_registry.register("system_info")
class SystemInfoCommand:
    """Displays system information (OS, uptime, hostname, CPU, Memory). Usage: system_info"""
    def run(self, args_str=""):
        # Use check_return_code=False for these commands as they might fail in restricted environments
        # but we still want to show whatever partial output or error they give.
        uname = _run_shell_command("uname -a", check_return_code=False)
        uptime = _run_shell_command("uptime", check_return_code=False)
        hostname = _run_shell_command("hostname", check_return_code=False)
        # Attempt to get CPU info, fallback if lscpu fails or isn't available
        cpu_info = _run_shell_command("lscpu | grep 'Model name' | cut -d: -f2- || echo 'CPU Info: Not available or permission denied.'", check_return_code=False)
        # Attempt to get Memory info, fallback if free fails or isn't available
        mem_info = _run_shell_command("free -h | grep 'Mem:' || echo 'Memory Info: Not available or permission denied.'", check_return_code=False)

        return (
            f"--- System ---\n"
            f"Hostname: {hostname.strip()}\n"
            f"OS Info: {uname.strip()}\n"
            f"CPU: {cpu_info.strip()}\n"
            f"Memory: {mem_info.strip()}\n"
            f"--- Uptime ---\n"
            f"{uptime.strip()}"
        )

@cmd_registry.register("disk_usage")
class DiskUsageCommand:
    """Shows disk space usage. Usage: disk_usage"""
    def run(self, args_str=""):
        return _run_shell_command("df -h", check_return_code=False) # Allow partial output/errors

@cmd_registry.register("ping_host")
class PingHostCommand:
    """Pings a host to check connectivity. Usage: ping_host <hostname_or_ip>"""
    def run(self, host):
        if not host:
            return "Error: ping_host requires a hostname or IP address."
        # Use -c 4 to limit to 4 packets, -W 1 (timeout 1 second) for faster failure
        # CRITICAL FIX: Use shlex.quote for host argument
        quoted_host = shlex.quote(host.strip())
        # Redirect stderr to stdout to capture all output, allow non-zero for network issues
        return _run_shell_command(f"ping -c 4 -W 1 {quoted_host} 2>&1", check_return_code=False)

@cmd_registry.register("help")
class HelpCommand:
    """Shows this help message."""
    def run(self, args_str=""):
        docs = cmd_registry.get_command_docs()
        help_text = "[bold cyan]Available Commands:[/bold cyan]\n\n"
        for name, doc in sorted(docs.items()):
            help_text += f"- [bold green]{name}[/bold green]: {doc}\n"
        help_text += "\nType a command followed by its arguments, or type any other prompt for the AI."
        help_text += "\n\n[dim]Special commands:[/dim]"
        help_text += "\n[dim]- 'multi': For multi-line input.[/dim]"
        help_text += "\n[dim]- 'exit' / 'quit': To end the session.[/dim]"
        return help_text

# ========== AI Assistant Call ==========
def ask_ai(prompt):
    """Sends a prompt to the AI and gets a response, maintaining conversation history."""
    global conversation_history
    log.info("Contacting AI...")

    # Dynamic date/time/location context
    from datetime import datetime
    current_time = datetime.now().strftime("%A, %B %d, %Y at %I:%M:%S %p %Z")
    current_location = "Entebbe, Central Region, Uganda" # Hardcoded for now, can be made dynamic later

    tool_docs = "\n".join([f"    - {name}: {doc}" for name, doc in cmd_registry.get_command_docs().items()])
    
    system_prompt = f"""You are ShellGPT-Pro, an advanced AI assistant integrated into a command-line.
Your goal is to help the user by using the available tools to perform tasks, gather information, and provide concise, helpful answers.

**Tool Usage Protocol:**
1.  **Identify if a tool is needed:** If the user's request requires interacting with the system (files, web, shell, Python execution, system info), you MUST use a tool.
2.  **Respond ONLY with a tool block:** If you decide to use a tool, your entire response MUST be formatted as follows, and nothing else:
    ```xml
    <tool>
    <name>tool_name</name>
    <args>tool_arguments</args>
    </tool>
    ```
    * Replace `tool_name` with the exact name of the tool.
    * Replace `tool_arguments` with the arguments for that tool.
    * **Crucial for `write_file` and multi-line content:** If the content for `write_file` contains newlines, they should be escaped as `\\n` within the `<args>` tag. For example:
        `<args>hello.py print(\\"Hello World!\\nThis is line two.\\")</args>`
    * Arguments containing spaces should **not** be quoted by you within the `<args>` tag; the system will handle quoting for the shell where necessary. Just provide the exact string argument.

3.  **Multi-step tasks:** For complex requests requiring multiple tools (e.g., "create a file and then run it"), you must make ONE tool call per response. The system will execute that tool, provide you with its output, and then you will decide the next step (either another tool call or a final answer). Do not try to chain tools directly in one response.

4.  **Final Answer:** Once a task is complete or you have gathered sufficient information, respond directly as a helpful assistant. Summarize your findings, the outcome of your actions, or directly answer the user's question. Do NOT include tool blocks if the task is finished.

**Available tools:**
{tool_docs}

**Current Context:**
- **Date and Time:** {current_time}
- **Location:** {current_location}

**Conversation History (Important for context):**
"""

    messages = [
        {"role": "system", "content": system_prompt},
        *conversation_history,
        {"role": "user", "content": prompt}
    ]

    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    payload = {"model": MODEL, "messages": messages, "max_tokens": 1500, "temperature": 0.7}

    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        response.raise_for_status()
        
        # Append user prompt and AI response to history
        conversation_history.append({"role": "user", "content": prompt})
        ai_response_message = response.json()["choices"][0]["message"]
        conversation_history.append(ai_response_message)

        return ai_response_message["content"].strip()
    except requests.exceptions.HTTPError as e:
        log.error(f"HTTP Error from AI API: {e.response.text}")
        return f"[red]❌ AI API Error:[/red] {e.response.text}"
    except Exception as e:
        log.critical(f"Failed to process AI response: {e}", exc_info=True)
        return f"[red]❌ AI Processing Error:[/red] {str(e)}"

# ========== Main Loop ==========
def main():
    if not API_KEY:
        log.critical("TOGETHER_API_KEY environment variable not set. Please set it and try again.")
        sys.exit(1) # Exit if API key is not set

    console.clear()
    console.print(Panel("🤖 [bold cyan]ShellGPT-Pro[/bold cyan] (v2.4 - Ultimate Fixed)", subtitle="[dim]Your Ultimate AI-Powered Command Line Assistant[/dim]", border_style="blue"))
    console.print(Markdown(HelpCommand().run("")))

    while True:
        try:
            console.print("\n[dim]Enter a prompt, 'multi' for multi-line, or 'exit' to quit.[/dim]")
            prompt = Prompt.ask("[bold blue]➤[/bold blue]")

            if prompt.lower().strip() in ["exit", "quit"]:
                console.print("[yellow]👋 Exiting. Your session log is in 'shellgpt_pro.log'.[/yellow]")
                break

            if prompt.lower().strip() == 'multi':
                console.print("[cyan]Enter multi-line input (End with Ctrl+D or Ctrl+Z on a new line):[/cyan]")
                lines = sys.stdin.readlines()
                prompt = "".join(lines).strip()
                if not prompt: 
                    console.print("[dim]No multi-line input provided. Try again.[/dim]")
                    continue
                console.print(Panel(prompt, title="[bold green]Multi-line Input[/bold green]", border_style="green", expand=False))

            # Check if the user is directly invoking a command
            parts = prompt.split(maxsplit=1)
            command_name = parts[0].lower() # Normalize command name
            args_str = parts[1].strip() if len(parts) > 1 else "" # Ensure args are stripped

            command = cmd_registry.get_command(command_name)
            if command:
                console.print(f"[bold cyan]User directly invoked:[/bold cyan] [bold yellow]{command_name}[/bold yellow] {args_str}")
                output = command.run(args_str)
                console.print(Panel(output, title=f"[bold green]📟 {command_name} Output[/bold green]", expand=False, border_style="green"))
                # If user directly runs a command, the history is updated, but no AI follow-up is automatically triggered.
            else:
                # If not a direct command, send to AI for processing
                ai_output = ask_ai(prompt)

                if ai_output.strip().startswith("<tool>"):
                    try:
                        tool_name_match = re.search(r"<name>(.*?)</name>", ai_output, re.DOTALL)
                        tool_args_match = re.search(r"<args>(.*?)</args>", ai_output, re.DOTALL)

                        if tool_name_match and tool_args_match:
                            tool_name = tool_name_match.group(1).strip()
                            tool_args = tool_args_match.group(1).strip()
                            
                            tool_command = cmd_registry.get_command(tool_name)

                            if tool_command:
                                console.print(f"[yellow]🤖 AI is using tool '[bold]{tool_name}[/bold]' with args: '[dim]{tool_args[:100]}{'...' if len(tool_args) > 100 else ''}[/dim]'[/yellow]")
                                tool_output = tool_command.run(tool_args)
                                console.print(Panel(tool_output, title=f"[bold green]🛠️ Tool Output ({tool_name})[/bold green]", expand=False, border_style="yellow"))

                                # AI follow-up: Ask the AI to summarize the tool output or determine next step
                                # Crucial: Pass the tool output back to the AI for its next decision
                                followup_prompt = (
                                    f"The user's original query was: '{prompt}'. "
                                    f"I just used the tool '{tool_name}' with arguments '{tool_args}' "
                                    f"and got this result:\n\n---\n{tool_output}\n---\n\n"
                                    f"Based on this result and the original query, what is the next logical step or final answer? "
                                    f"If the task is complete, provide a concise summary of the outcome. "
                                    f"If another tool is needed, respond with the next <tool> block. "
                                    f"Do NOT provide simulated tool outputs; always provide actual tool calls if needed."
                                )
                                # IMPORTANT: The response from this second `ask_ai` call will be processed here as a final AI response.
                                # If the AI decides to chain another tool, it will effectively cause another AI interaction loop step.
                                final_answer_or_next_tool_call = ask_ai(followup_prompt) 
                                
                                # This handles potential chaining. If the AI responds with another tool call, execute it.
                                # This creates a single level of AI-driven tool chaining. For deeper chaining,
                                # you might need a more complex state machine or recursive function.
                                if final_answer_or_next_tool_call.strip().startswith("<tool>"):
                                    console.print("[cyan]🤖 AI decided to chain another tool based on previous output.[/cyan]")
                                    try:
                                        chained_tool_name_match = re.search(r"<name>(.*?)</name>", final_answer_or_next_tool_call, re.DOTALL)
                                        chained_tool_args_match = re.search(r"<args>(.*?)</args>", final_answer_or_next_tool_call, re.DOTALL)

                                        if chained_tool_name_match and chained_tool_args_match:
                                            chained_tool_name = chained_tool_name_match.group(1).strip()
                                            chained_tool_args = chained_tool_args_match.group(1).strip()
                                            
                                            chained_command = cmd_registry.get_command(chained_tool_name)
                                            if chained_command:
                                                console.print(f"[yellow]🤖 AI is chaining tool '[bold]{chained_tool_name}[/bold]' with args: '[dim]{chained_tool_args[:100]}{'...' if len(chained_tool_args) > 100 else ''}[/dim]'[/yellow]")
                                                chained_tool_output = chained_command.run(chained_tool_args)
                                                console.print(Panel(chained_tool_output, title=f"[bold green]🛠️ Chained Tool Output ({chained_tool_name})[/bold green]", expand=False, border_style="green"))
                                                
                                                # Final follow-up after the chained tool
                                                final_summary_prompt = (
                                                    f"The user's original query was: '{prompt}'. "
                                                    f"I used a sequence of tools. The last tool used was '{chained_tool_name}' "
                                                    f"with arguments '{chained_tool_args}', and its result was:\n\n---\n{chained_tool_output}\n---\n\n"
                                                    f"Please provide the final, concise answer or summary to the user based on all actions taken."
                                                )
                                                final_response = ask_ai(final_summary_prompt)
                                                console.print(Panel(Markdown(final_response), title="[bold magenta]🤖 AI Final Response[/bold magenta]", expand=False, border_style="magenta"))
                                            else:
                                                console.print(f"[red]❌ AI tried to chain an unknown tool: {chained_tool_name}[/red]")
                                                console.print(Panel(Markdown(final_answer_or_next_tool_call), title="[bold magenta]🤖 AI Response (Chained Unknown Tool)[/bold magenta]", expand=False, border_style="red"))
                                        else:
                                            console.print(f"[red]❌ AI tried to chain a tool, but the format was incorrect.[/red]")
                                            console.print(Panel(Markdown(final_answer_or_next_tool_call), title="[bold magenta]🤖 AI Response (Chained Tool Format Error)[/bold magenta]", expand=False, border_style="red"))
                                    except Exception as chained_parse_e:
                                        log.error(f"Error parsing chained AI tool response: {chained_parse_e}", exc_info=True)
                                        console.print(f"[red]❌ Error parsing AI's chained tool usage. Details: {chained_parse_e}[/red]")
                                        console.print(Panel(Markdown(final_answer_or_next_tool_call), title="[bold magenta]🤖 AI Response (Chained Tool Parse Error)[/bold magenta]", expand=False, border_style="red"))
                                else:
                                    # If the AI's follow-up was a direct answer, display it
                                    console.print(Panel(Markdown(final_answer_or_next_tool_call), title="[bold magenta]🤖 AI Response[/bold magenta]", expand=False, border_style="magenta"))
                            else:
                                console.print(f"[red]❌ AI tried to use an unknown tool: {tool_name}[/red]")
                                console.print(Panel(Markdown(ai_output), title="[bold magenta]🤖 AI Response (Unknown Tool)[/bold magenta]", expand=False, border_style="red"))
                        else:
                            console.print(f"[red]❌ AI tried to use a tool, but the format was incorrect or incomplete. AI output:\n{ai_output}[/red]")
                            console.print(Panel(Markdown(ai_output), title="[bold magenta]🤖 AI Response (Tool Format Error)[/bold magenta]", expand=False, border_style="red"))
                    except Exception as parse_e:
                        log.error(f"Error parsing AI tool response: {parse_e}", exc_info=True)
                        console.print(f"[red]❌ Error parsing AI's tool usage. Details: {parse_e}[/red]")
                        console.print(Panel(Markdown(ai_output), title="[bold magenta]🤖 AI Response (Tool Parse Error)[/bold magenta]", expand=False, border_style="red"))
                else:
                    # AI responded directly without a tool
                    console.print(Panel(Markdown(ai_output), title="[bold magenta]🤖 AI Response[/bold magenta]", expand=False, border_style="magenta"))

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user. Type 'exit' to quit.[/yellow]")
        except Exception as e:
            log.error(f"An unexpected error occurred in the main loop: {e}", exc_info=True)
            console.print(f"[bold red]❌ An unexpected error occurred. Check 'shellgpt_pro.log' for details.[/bold red]")


if __name__ == "__main__":
    main()

