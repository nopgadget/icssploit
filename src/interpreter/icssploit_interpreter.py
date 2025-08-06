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
        self.completion_engine = CompletionEngine(self.module_manager, self.client_manager)
        self.module_command_handler = ModuleCommandHandler(self.module_manager)
        self.search_engine = SearchEngine(self.module_manager)
        self.client_command_handler = ClientCommandHandler(self.client_manager)
        self.show_command_handler = ShowCommandHandler(self.module_manager, self.client_manager)
        
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
        elif self.client_manager.get_current_client():
            utils.print_info("\n", self.display_manager.get_client_help())

    def command_use(self, target_path, *args, **kwargs):
        """Use a module or client"""
        # Check if this is a client use command
        if target_path.startswith('client/'):
            client_type = target_path.split('/')[1]
            # Parse additional arguments as client options
            client_options = {}
            for arg in args:
                if '=' in arg:
                    key, value = arg.split('=', 1)
                    # Try to convert to int if possible
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                    client_options[key] = value
            
            self.client_manager.use_client(client_type, **client_options)
        else:
            # Use as module (existing behavior)
            self.module_manager.use_module(target_path)
            # Update current_module reference for backward compatibility
            self.current_module = self.module_manager.current_module

    def command_back(self, *args, **kwargs):
        """Go back to global context"""
        # Check if we have a current client
        if self.client_manager.get_current_client():
            self.client_manager.back()
        else:
            # Use module back (existing behavior)
            self.module_manager.back()
            # Update current_module reference for backward compatibility
            self.current_module = self.module_manager.current_module

    def command_exit(self, *args, **kwargs):
        """Exit the interpreter"""
        # Check for problematic clients before cleanup
        force_exit = False
        try:
            if hasattr(self, 'client_manager') and self.client_manager and self.client_manager.clients:
                for name, client in self.client_manager.clients.items():
                    if 'OPCUAClient' in str(type(client)):
                        force_exit = True
                        break
        except:
            pass
        
        if force_exit:
            # OPC UA client detected - skip cleanup and force exit immediately
            utils.print_info()
            utils.print_status("icssploit stopped")
            os._exit(0)
        else:
            # Normal cleanup for other clients
            self._cleanup_on_exit()
            raise EOFError
    
    def _cleanup_on_exit(self):
        """Cleanup method called before exiting"""
        try:
            if hasattr(self, 'client_manager') and self.client_manager:
                self.client_manager.cleanup_all_clients()
        except Exception as e:
            utils.print_error(f"Error during cleanup: {e}")
    
    def start(self):
        """Override start method to add cleanup on exit"""
        import atexit
        
        # Register a force exit handler as the very last thing
        def emergency_exit():
            """Emergency exit if normal cleanup hangs"""
            try:
                # Quick check if we have any OPC UA clients that might hang
                if hasattr(self, 'client_manager') and self.client_manager and self.client_manager.clients:
                    for name, client in self.client_manager.clients.items():
                        if hasattr(client, '_client') and client._client:
                            # We have OPC UA clients - force exit to prevent hanging
                            os._exit(0)
            except:
                pass
        
        atexit.register(emergency_exit)
        
        try:
            super().start()
        except KeyboardInterrupt:
            utils.print_info()
            utils.print_status("icssploit interrupted")
            self._cleanup_on_exit()
            # Force exit immediately after cleanup for OPC UA clients
            self._force_exit_if_needed()
        except EOFError:
            utils.print_info()
            utils.print_status("icssploit stopped")
            self._cleanup_on_exit()
            # Force exit immediately after cleanup for OPC UA clients
            self._force_exit_if_needed()
        except Exception as e:
            utils.print_error(f"Unexpected error: {e}")
            self._cleanup_on_exit()
            raise
    
    def _force_exit_if_needed(self):
        """Force exit if we have problematic clients like OPC UA"""
        try:
            if hasattr(self, 'client_manager') and self.client_manager and self.client_manager.clients:
                for name, client in self.client_manager.clients.items():
                    # Check for OPC UA clients which are known to hang
                    if 'OPCUAClient' in str(type(client)):
                        # OPC UA client detected - force exit to prevent hanging
                        os._exit(0)
        except:
            pass

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

    # Client command handlers (delegated to ClientCommandHandler)
    def command_connect(self, *args, **kwargs):
        """Connect current client"""
        self.client_command_handler.connect(*args, **kwargs)

    def command_disconnect(self, *args, **kwargs):
        """Disconnect current client"""
        self.client_command_handler.disconnect(*args, **kwargs)

    def command_send(self, *args, **kwargs):
        """Send message to current client"""
        self.client_command_handler.send(*args, **kwargs)

    def command_receive(self, *args, **kwargs):
        """Receive message from current client"""
        self.client_command_handler.receive(*args, **kwargs)

    def command_call(self, *args, **kwargs):
        """Call method on current client"""
        self.client_command_handler.call(*args, **kwargs)
    
    def complete_call(self, text, line, start_index, end_index):
        """Tab completion for call command when in client context"""
        current_client = self.client_manager.get_current_client()
        if not current_client:
            return []
        
        # Get available methods from the current client
        methods = []
        for method_name in dir(current_client):
            # Skip private methods and non-callable attributes
            if not method_name.startswith('_') and callable(getattr(current_client, method_name)):
                # Only include methods that are likely to be user-callable
                # Skip some internal methods
                if method_name not in ['logger', 'connect', 'disconnect', 'check', 'run']:
                    methods.append(method_name)
        
        # Filter methods that start with the text
        return [method for method in methods if method.startswith(text)]

    def command_set(self, *args, **kwargs):
        """Set a client option"""
        # Check if we have a current client
        if self.client_manager.get_current_client():
            self.client_command_handler.set(*args, **kwargs)
        else:
            # Use module set (existing behavior)
            if not self.module_manager.current_module:
                utils.print_error("You have to activate any module with 'use' command.")
                return
            self.module_command_handler.set(*args, **kwargs)

    def command_setg(self, *args, **kwargs):
        """Set a global option"""
        # Check if we have a current client
        if self.client_manager.get_current_client():
            self.client_command_handler.setg(*args, **kwargs)
        else:
            # Use module setg (existing behavior)
            if not self.module_manager.current_module:
                utils.print_error("You have to activate any module with 'use' command.")
                return
            self.module_command_handler.setg(*args, **kwargs)

    def command_unsetg(self, *args, **kwargs):
        """Unset a global option"""
        # Check if we have a current client
        if self.client_manager.get_current_client():
            self.client_command_handler.unsetg(*args, **kwargs)
        else:
            # Use module unsetg (existing behavior)
            self.module_command_handler.unsetg(*args, **kwargs)

    def command_options(self, *args, **kwargs):
        """Show client options"""
        # Check if we have a current client
        if self.client_manager.get_current_client():
            self.client_command_handler.options(*args, **kwargs)
        else:
            # Use module options (existing behavior)
            if not self.module_manager.current_module:
                utils.print_error("You have to activate any module with 'use' command.")
                return
            self.module_command_handler.options(*args, **kwargs)

    def command_run(self, *args, **kwargs):
        """Run the current module or client"""
        # Check if we have a current client
        if self.client_manager.get_current_client():
            self.client_command_handler.run(*args, **kwargs)
        else:
            # Use module run (existing behavior)
            if not self.module_manager.current_module:
                utils.print_error("You have to activate any module with 'use' command.")
                return
            self.module_command_handler.run(*args, **kwargs)

    def command_exploit(self, *args, **kwargs):
        """Alias for run command"""
        self.command_run(*args, **kwargs)

    def command_check(self, *args, **kwargs):
        """Check if target is vulnerable or reachable"""
        # Check if we have a current client
        if self.client_manager.get_current_client():
            self.client_command_handler.check(*args, **kwargs)
        else:
            # Use module check (existing behavior)
            if not self.module_manager.current_module:
                utils.print_error("You have to activate any module with 'use' command.")
                return
            self.module_command_handler.check(*args, **kwargs)

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