import traceback
import sys
from src import utils
from src.exploits import GLOBAL_OPTS


class ClientCommandHandler:
    """Handles client-specific commands with options support"""
    
    def __init__(self, client_manager):
        self.client_manager = client_manager

    @utils.client_required
    def connect(self, *args, **kwargs):
        """Connect current client"""
        current_client = self.client_manager.get_current_client()
        if self.client_manager.connect_client(current_client.name):
            utils.print_success(f"Connected to {current_client.name}")
        else:
            utils.print_error(f"Failed to connect to {current_client.name}")

    @utils.client_required
    def disconnect(self, *args, **kwargs):
        """Disconnect current client"""
        current_client = self.client_manager.get_current_client()
        if self.client_manager.disconnect_client(current_client.name):
            utils.print_success(f"Disconnected from {current_client.name}")
        else:
            utils.print_error(f"Failed to disconnect from {current_client.name}")

    @utils.client_required
    def send(self, *args, **kwargs):
        """Send message to current client"""
        current_client = self.client_manager.get_current_client()
        
        if not args:
            utils.print_error("Usage: send <message>")
            return
        
        message = args[0]
        try:
            if hasattr(current_client, 'send_message'):
                result = current_client.send_message(message)
                utils.print_success(f"Message sent: {result}")
            else:
                utils.print_error(f"Client {current_client.__class__.__name__} does not support send_message")
        except Exception as e:
            utils.print_error(f"Error sending message: {e}")

    @utils.client_required
    def receive(self, *args, **kwargs):
        """Receive message from current client"""
        current_client = self.client_manager.get_current_client()
        
        try:
            if hasattr(current_client, 'receive_message'):
                result = current_client.receive_message()
                utils.print_success(f"Received: {result}")
            else:
                utils.print_error(f"Client {current_client.__class__.__name__} does not support receive_message")
        except Exception as e:
            utils.print_error(f"Error receiving message: {e}")

    @utils.client_required
    def call(self, *args, **kwargs):
        """Call method on current client"""
        current_client = self.client_manager.get_current_client()
        
        if len(args) < 1:
            utils.print_error("Usage: call <method_name> [args...]")
            return
        
        method_name = args[0]
        method_args = args[1:]
        
        try:
            if hasattr(current_client, method_name):
                method = getattr(current_client, method_name)
                result = method(*method_args)
                utils.print_success(f"Method {method_name} returned: {result}")
            else:
                utils.print_error(f"Method {method_name} not found on client {current_client.__class__.__name__}")
        except Exception as e:
            utils.print_error(f"Error calling {method_name}: {e}")

    @utils.client_required
    def set(self, *args, **kwargs):
        """Set a client option"""
        current_client = self.client_manager.get_current_client()
        
        if not args:
            utils.print_error("Usage: set <option> <value>")
            return
        
        key, _, value = args[0].partition(' ')
        if hasattr(current_client, 'options') and key in current_client.options:
            setattr(current_client, key, value)
            if kwargs.get("glob", False):
                GLOBAL_OPTS[key] = value
            utils.print_success({key: value})
        else:
            available_options = getattr(current_client, 'options', [])
            utils.print_error("You can't set option '{}'.\n"
                              "Available options: {}".format(key, available_options))

    def setg(self, *args, **kwargs):
        """Set a global option"""
        kwargs['glob'] = True
        self.set(*args, **kwargs)

    def unsetg(self, *args, **kwargs):
        """Unset a global option"""
        key, _, value = args[0].partition(' ')
        try:
            del GLOBAL_OPTS[key]
        except KeyError:
            utils.print_error("You can't unset global option '{}'.\n"
                              "Available global options: {}".format(key, GLOBAL_OPTS.keys()))
        else:
            utils.print_success({key: value})

    @utils.client_required
    def options(self, *args, **kwargs):
        """Show client options"""
        self._show_options(*args, **kwargs)

    def _show_options(self, *args, **kwargs):
        """Show client options in a formatted table"""
        current_client = self.client_manager.get_current_client()
        
        if not hasattr(current_client, 'options'):
            utils.print_info("This client does not have configurable options")
            return
        
        target_opts = ['target', 'port']
        client_opts = [opt for opt in current_client.options if opt not in target_opts]
        headers = ("Name", "Current settings", "Description")

        utils.print_info('\nTarget options:')
        utils.print_table(headers, *self._get_opts(current_client, *target_opts))

        if client_opts:
            utils.print_info('\nClient options:')
            utils.print_table(headers, *self._get_opts(current_client, *client_opts))

        utils.print_info()

    def _get_opts(self, client, *args):
        """Generator returning client's Option attributes (option_name, option_value, option_description)"""
        for opt_key in args:
            try:
                opt_value = getattr(client, opt_key)
                # Get the Option instance from the class using __dict__ to avoid triggering __get__
                option_instance = client.__class__.__dict__.get(opt_key)
                if option_instance and hasattr(option_instance, 'description'):
                    opt_description = option_instance.description
                else:
                    opt_description = "No description available"
                yield opt_key, opt_value, opt_description
            except (AttributeError, KeyError):
                # If we can't get the description, use a default
                opt_description = "No description available"
                opt_value = getattr(client, opt_key, "Not set")
                yield opt_key, opt_value, opt_description

    def run(self, *args, **kwargs):
        """Run the current client (connect and perform default operation)"""
        current_client = self.client_manager.get_current_client()
        utils.print_status("Running client...")
        try:
            # Try to connect first
            if self.client_manager.connect_client(current_client.name):
                utils.print_success(f"Connected to {current_client.name}")
                
                # If client has a run method, call it
                if hasattr(current_client, 'run'):
                    current_client.run()
                else:
                    utils.print_info("Client connected successfully. Use 'send', 'receive', or 'call' commands.")
            else:
                utils.print_error(f"Failed to connect to {current_client.name}")
                utils.print_info("Check that:")
                utils.print_info("  - Target address is correct")
                utils.print_info("  - Port is open and accessible")
                utils.print_info("  - Server is running and accepting connections")
                utils.print_info("  - Firewall is not blocking the connection")
        except KeyboardInterrupt:
            utils.print_info()
            utils.print_error("Operation cancelled by user")
        except Exception as e:
            utils.print_error(f"Unexpected error: {e}")
            utils.print_error(traceback.format_exc(sys.exc_info()))

    def exploit(self, *args, **kwargs):
        """Alias for run command"""
        self.run(*args, **kwargs)

    @utils.client_required
    def check(self, *args, **kwargs):
        """Check if client can connect to target"""
        current_client = self.client_manager.get_current_client()
        try:
            if hasattr(current_client, 'check'):
                result = current_client.check()
            else:
                # Default check: try to connect
                result = self.client_manager.connect_client(current_client.name)
                if result:
                    self.client_manager.disconnect_client(current_client.name)
        except Exception as error:
            utils.print_error(f"Check failed: {error}")
        else:
            if result is True:
                utils.print_success("Target is reachable")
            elif result is False:
                utils.print_error("Target is not reachable")
                utils.print_info("Possible issues:")
                utils.print_info("  - Target address is incorrect")
                utils.print_info("  - Port is closed or blocked")
                utils.print_info("  - Server is not running")
                utils.print_info("  - Network connectivity issues")
            else:
                utils.print_status("Target could not be verified") 