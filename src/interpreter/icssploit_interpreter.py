import os
import sys
import itertools
import traceback
import atexit
from collections import Counter

from src.printer import PrinterThread, printer_queue
from src.exceptions import icssploitException
from src.exploits import GLOBAL_OPTS
from src import utils
from src.config import GITHUB_URL, APP_VERSION, DEFAULT_PROMPT_HOSTNAME, HISTORY_FILE

try:
    if sys.platform == "darwin":
        import gnureadline as readline
    elif sys.platform == "win32":
        try:
            import readline
        except ImportError:
            try:
                import pyreadline3 as readline
            except ImportError:
                try:
                    import pyreadline as readline
                except ImportError:
                    readline = None
    else:
        import readline
except ImportError:
    # readline is not available
    readline = None

from .base_interpreter import BaseInterpreter
from .module_manager import ModuleManager
from .display_manager import DisplayManager
from .completion_engine import CompletionEngine
from .module_command_handler import ModuleCommandHandler
from .search_engine import SearchEngine
from .client_command_handler import ClientCommandHandler
from .show_command_handler import ShowCommandHandler


class IcssploitInterpreter(BaseInterpreter):
    """Main interpreter class that orchestrates all specialized handlers"""
    
    history_file = os.path.expanduser(HISTORY_FILE)

    def __init__(self, extra_package_path=None):
        super(IcssploitInterpreter, self).__init__()
        PrinterThread().start()
        
        # Initialize client manager
        from src.client_manager import ClientManager
        self.client_manager = ClientManager()
        
        # Initialize all specialized handlers
        self.module_manager = ModuleManager(extra_package_path)
        self.display_manager = DisplayManager(self.module_manager, self.client_manager)
        self.completion_engine = CompletionEngine(self.module_manager)
        self.module_command_handler = ModuleCommandHandler(self.module_manager)
        self.search_engine = SearchEngine(self.module_manager)
        self.client_command_handler = ClientCommandHandler(self.client_manager)
        self.show_command_handler = ShowCommandHandler(self.module_manager)
        
        # Set banner
        self.banner = self.display_manager.get_banner()
        
        # Set current_module reference for backward compatibility
        self.current_module = self.module_manager.current_module

    @property
    def prompt(self):
        """Get the current prompt string"""
        return self.display_manager.get_prompt()

    def get_command_handler(self, command):
        """Get the appropriate command handler"""
        try:
            command_handler = getattr(self, "command_{}".format(command))
        except AttributeError:
            try:
                command_handler = getattr(self.module_manager.current_module, "command_{}".format(command))
            except AttributeError:
                raise icssploitException("Unknown command: '{}'".format(command))
        return command_handler

    def suggested_commands(self):
        """Get suggested commands based on current context"""
        return self.completion_engine.suggested_commands()

    # Global command handlers
    def command_help(self, *args, **kwargs):
        """Show help information"""
        utils.print_info(self.display_manager.get_global_help())
        if self.module_manager.current_module:
            utils.print_info("\n", self.display_manager.get_module_help())

    def command_use(self, module_path, *args, **kwargs):
        """Use a module"""
        self.module_manager.use_module(module_path)
        # Update current_module reference for backward compatibility
        self.current_module = self.module_manager.current_module

    def command_back(self, *args, **kwargs):
        """Go back to global context"""
        self.module_manager.back()
        # Update current_module reference for backward compatibility
        self.current_module = self.module_manager.current_module

    def command_exit(self, *args, **kwargs):
        """Exit the interpreter"""
        raise EOFError

    def command_exec(self, *args, **kwargs):
        """Execute a shell command"""
        os.system(args[0])

    def command_search(self, *args, **kwargs):
        """Search for modules"""
        self.search_engine.search(args[0])

    def command_show(self, *args, **kwargs):
        """Show information"""
        self.show_command_handler.handle_show_command(args)

    def command_client(self, *args, **kwargs):
        """Handle client commands"""
        self.client_command_handler.handle_client_command(args)

    # Module command handlers (delegated to ModuleCommandHandler)
    def command_run(self, *args, **kwargs):
        """Run the current module"""
        # Check if module is loaded before calling decorated method
        if not self.module_manager.current_module:
            utils.print_error("You have to activate any module with 'use' command.")
            return
        self.module_command_handler.run(*args, **kwargs)

    def command_exploit(self, *args, **kwargs):
        """Alias for run command"""
        self.command_run(*args, **kwargs)

    def command_set(self, *args, **kwargs):
        """Set a module option"""
        # Check if module is loaded before calling decorated method
        if not self.module_manager.current_module:
            utils.print_error("You have to activate any module with 'use' command.")
            return
        self.module_command_handler.set(*args, **kwargs)

    def command_setg(self, *args, **kwargs):
        """Set a global option"""
        # Check if module is loaded before calling decorated method
        if not self.module_manager.current_module:
            utils.print_error("You have to activate any module with 'use' command.")
            return
        self.module_command_handler.setg(*args, **kwargs)

    def command_unsetg(self, *args, **kwargs):
        """Unset a global option"""
        self.module_command_handler.unsetg(*args, **kwargs)

    def command_check(self, *args, **kwargs):
        """Check if target is vulnerable"""
        # Check if module is loaded before calling decorated method
        if not self.module_manager.current_module:
            utils.print_error("You have to activate any module with 'use' command.")
            return
        self.module_command_handler.check(*args, **kwargs)

    def command_options(self, *args, **kwargs):
        """Show module options"""
        # Check if module is loaded before calling decorated method
        if not self.module_manager.current_module:
            utils.print_error("You have to activate any module with 'use' command.")
            return
        self.module_command_handler.options(*args, **kwargs)

    # Completion handlers (delegated to CompletionEngine)
    def complete_use(self, text, *args, **kwargs):
        """Complete use command"""
        return self.completion_engine.complete_use(text, *args, **kwargs)

    def complete_set(self, text, *args, **kwargs):
        """Complete set command"""
        return self.completion_engine.complete_set(text, *args, **kwargs)

    def complete_setg(self, text, *args, **kwargs):
        """Complete setg command"""
        return self.completion_engine.complete_setg(text, *args, **kwargs)

    def complete_unsetg(self, text, *args, **kwargs):
        """Complete unsetg command"""
        return self.completion_engine.complete_unsetg(text, *args, **kwargs)

    def complete_show(self, text, *args, **kwargs):
        """Complete show command"""
        return self.completion_engine.complete_show(text, *args, **kwargs)

    def complete_search(self, text, *args, **kwargs):
        """Complete search command"""
        return self.completion_engine.complete_search(text, *args, **kwargs)

    def complete_client(self, text, *args, **kwargs):
        """Complete client command"""
        return self.completion_engine.complete_client(text, *args, **kwargs) 