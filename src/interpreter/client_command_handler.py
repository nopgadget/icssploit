from src import utils


class ClientCommandHandler:
    """Handles all client-related commands"""
    
    def __init__(self, client_manager):
        self.client_manager = client_manager

    def handle_client_command(self, args):
        """Handle client management commands"""
        if not args:
            self._show_client_help()
            return

        # Parse the arguments properly - args[0] contains the full argument string
        arg_string = args[0]
        arg_list = arg_string.split()
        
        if not arg_list:
            self._show_client_help()
            return

        sub_command = arg_list[0].lower()
        
        if sub_command == 'create':
            self._handle_create(arg_list)
        elif sub_command == 'list':
            self._handle_list()
        elif sub_command == 'use':
            self._handle_use(arg_list)
        elif sub_command == 'connect':
            self._handle_connect(arg_list)
        elif sub_command == 'disconnect':
            self._handle_disconnect(arg_list)
        elif sub_command == 'remove':
            self._handle_remove(arg_list)
        elif sub_command == 'info':
            self._handle_info(arg_list)
        elif sub_command == 'help':
            self._handle_help(arg_list)
        elif sub_command == 'types':
            self._handle_types()
        elif sub_command == 'call':
            self._handle_call(arg_list)
        else:
            utils.print_error(f"Unknown client sub-command: {sub_command}")
            utils.print_info("Use 'client' without arguments to see available commands")

    def _show_client_help(self):
        """Show client command help"""
        utils.print_info("Client management commands:")
        utils.print_info("  client create <type> <name> [options]  Create a new client")
        utils.print_info("  client list                              List all clients")
        utils.print_info("  client use <name>                        Set current client")
        utils.print_info("  client connect <name>                    Connect a client")
        utils.print_info("  client disconnect <name>                 Disconnect a client")
        utils.print_info("  client remove <name>                     Remove a client")
        utils.print_info("  client info <name>                       Show client information")
        utils.print_info("  client help <type>                       Show client type help")
        utils.print_info("  client types                             List available client types")
        utils.print_info("  client call <name> <method> [args]      Call client method")

    def _handle_create(self, arg_list):
        """Handle client create command"""
        if len(arg_list) < 3:
            utils.print_error("Usage: client create <type> <name> [options]")
            return
        
        client_type = arg_list[1]
        client_name = arg_list[2]
        
        # Parse additional options
        options = {}
        for arg in arg_list[3:]:
            if '=' in arg:
                key, value = arg.split('=', 1)
                # Try to convert to int if possible
                try:
                    value = int(value)
                except ValueError:
                    pass
                options[key] = value
        
        client = self.client_manager.create_client(client_type, client_name, **options)
        if client:
            utils.print_success(f"Created {client_type} client: {client_name}")
        else:
            utils.print_error(f"Failed to create {client_type} client")

    def _handle_list(self):
        """Handle client list command"""
        clients = self.client_manager.list_clients()
        if not clients:
            utils.print_info("No clients created")
            return
        
        utils.print_info("Available clients:")
        for name, info in clients.items():
            status = "✓" if info['connected'] else "✗"
            current = " (current)" if info['current'] else ""
            utils.print_info(f"  {name} ({info['type']}) {status}{current}")
            if 'ip' in info:
                utils.print_info(f"    IP: {info['ip']}:{info.get('port', 'Unknown')}")

    def _handle_use(self, arg_list):
        """Handle client use command"""
        if len(arg_list) < 2:
            utils.print_error("Usage: client use <name>")
            return
        
        client_name = arg_list[1]
        if self.client_manager.set_current_client(client_name):
            utils.print_success(f"Current client set to: {client_name}")
        else:
            utils.print_error(f"Client not found: {client_name}")

    def _handle_connect(self, arg_list):
        """Handle client connect command"""
        if len(arg_list) < 2:
            utils.print_error("Usage: client connect <name>")
            return
        
        client_name = arg_list[1]
        if self.client_manager.connect_client(client_name):
            utils.print_success(f"Connected client: {client_name}")
        else:
            utils.print_error(f"Failed to connect client: {client_name}")

    def _handle_disconnect(self, arg_list):
        """Handle client disconnect command"""
        if len(arg_list) < 2:
            utils.print_error("Usage: client disconnect <name>")
            return
        
        client_name = arg_list[1]
        if self.client_manager.disconnect_client(client_name):
            utils.print_success(f"Disconnected client: {client_name}")
        else:
            utils.print_error(f"Failed to disconnect client: {client_name}")

    def _handle_remove(self, arg_list):
        """Handle client remove command"""
        if len(arg_list) < 2:
            utils.print_error("Usage: client remove <name>")
            return
        
        client_name = arg_list[1]
        if self.client_manager.remove_client(client_name):
            utils.print_success(f"Removed client: {client_name}")
        else:
            utils.print_error(f"Failed to remove client: {client_name}")

    def _handle_info(self, arg_list):
        """Handle client info command"""
        if len(arg_list) < 2:
            utils.print_error("Usage: client info <name>")
            return
        
        client_name = arg_list[1]
        info = self.client_manager.get_client_info(client_name)
        if info:
            utils.print_info(f"Client: {info['name']}")
            utils.print_info(f"Type: {info['type']}")
            utils.print_info(f"Connected: {'Yes' if info['connected'] else 'No'}")
            utils.print_info(f"Current: {'Yes' if info['current'] else 'No'}")
            for key, value in info.items():
                if key not in ['name', 'type', 'connected', 'current']:
                    utils.print_info(f"{key.title()}: {value}")
        else:
            utils.print_error(f"Client not found: {client_name}")

    def _handle_help(self, arg_list):
        """Handle client help command"""
        if len(arg_list) < 2:
            utils.print_error("Usage: client help <type>")
            return
        
        client_type = arg_list[1]
        help_text = self.client_manager.get_client_help(client_type)
        utils.print_info(help_text)

    def _handle_types(self):
        """Handle client types command"""
        client_types = self.client_manager.get_available_clients()
        utils.print_info("Available client types:")
        for client_type in client_types:
            utils.print_info(f"  {client_type}")

    def _handle_call(self, arg_list):
        """Handle client call command"""
        if len(arg_list) < 3:
            utils.print_error("Usage: client call <name> <method> [args...]")
            return
        
        client_name = arg_list[1]
        method_name = arg_list[2]
        method_args = arg_list[3:]
        
        result = self.client_manager.execute_client_method(client_name, method_name, *method_args)
        if result is not None:
            utils.print_info(f"Result: {result}")
        else:
            utils.print_error(f"Failed to execute {method_name} on {client_name}") 