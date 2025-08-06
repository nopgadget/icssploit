import traceback
import sys
from src import utils
from src.exploits import GLOBAL_OPTS


class ClientCommandHandler:
    """Handles client-specific commands with options support"""
    
    def __init__(self, client_manager):
        self.client_manager = client_manager

    def handle_client_command(self, args):
        """Handle client command with sub-commands"""
        if not args:
            utils.print_error("Usage: client <type> [name] or client <command>")
            utils.print_info("Available client types: {}".format(", ".join(self.client_manager.get_available_clients())))
            utils.print_info("Available commands: connect, disconnect, set, options, run, check, call, send, receive")
            return
        
        # Split args string into individual arguments
        if isinstance(args, str):
            args = args.split()
        
        sub_command = args[0]
        
        # Check if it's a client type (for creating new clients)
        if sub_command in self.client_manager.get_available_clients():
            # Parse client name if provided
            client_name = args[1] if len(args) > 1 else None
            self.client_manager.use_client(sub_command, client_name)
            return
        
        # Check if it's a client command
        try:
            method = getattr(self, sub_command)
            method(*args[1:])
        except AttributeError:
            utils.print_error("Unknown client command '{}'. ".format(sub_command))
            utils.print_info("Available client types: {}".format(", ".join(self.client_manager.get_available_clients())))
            utils.print_info("Available commands: connect, disconnect, set, options, run, check, call, send, receive")

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
        
        # Handle case where args comes as a single string from parse_line
        if len(args) == 1 and isinstance(args[0], str):
            args = args[0].split()
        
        if len(args) < 1:
            utils.print_error("Usage: call <method_name> [args...]")
            return
        
        method_name = args[0]
        method_args = args[1:]
        
        # Convert string arguments to appropriate types
        converted_args = []
        for arg in method_args:
            try:
                # Try to convert to int first
                converted_args.append(int(arg))
            except ValueError:
                try:
                    # Try to convert to float
                    converted_args.append(float(arg))
                except ValueError:
                    # Keep as string
                    converted_args.append(arg)
        
        try:
            if hasattr(current_client, method_name):
                method = getattr(current_client, method_name)
                result = method(*converted_args)
                
                # Format the result for better readability
                self._format_method_result(method_name, result, current_client)
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
    
    def _format_method_result(self, method_name: str, result, client):
        """Format method results for better readability"""
        
        # Special formatting for OPC UA methods
        if hasattr(client, '__class__') and 'OPCUAClient' in client.__class__.__name__:
            if method_name == "enumerate_device" and isinstance(result, dict):
                self._format_opcua_enumerate_result(result)
                return
            elif method_name == "browse_nodes" and isinstance(result, list):
                self._format_opcua_browse_nodes_result(result)
                return
            elif method_name == "get_server_info" and isinstance(result, dict):
                self._format_opcua_server_info_result(result)
                return
            elif method_name == "get_target_info" and isinstance(result, tuple):
                self._format_opcua_target_info_result(result)
                return
        
        # Default formatting for other results
        utils.print_success(f"Method {method_name} returned: {result}")
    
    def _format_opcua_enumerate_result(self, nodes_by_path: dict):
        """Format OPC UA enumerate_device results in a human-readable way"""
        
        if not nodes_by_path:
            utils.print_status("No nodes found or enumeration failed")
            return
        
        utils.print_success("OPC UA Device Enumeration Results:")
        utils.print_info("=" * 60)
        
        for path_name, nodes in nodes_by_path.items():
            if not nodes:
                continue
                
            utils.print_info(f"\n📁 {path_name.upper()} ({len(nodes)} nodes)")
            utils.print_info("-" * 40)
            
            for i, node in enumerate(nodes, 1):
                # Handle both OPCUANode objects and other node types
                if hasattr(node, 'node_id'):
                    node_id = node.node_id
                    browse_name = node.browse_name
                    display_name = node.display_name
                    node_class = node.node_class
                    data_type = getattr(node, 'data_type', None)
                    value = getattr(node, 'value', None)
                else:
                    # Fallback for other node representations
                    node_id = str(node)
                    browse_name = str(node)
                    display_name = str(node)
                    node_class = "Unknown"
                    data_type = None
                    value = None
                
                utils.print_info(f"  {i:2d}. {browse_name}")
                utils.print_info(f"      ID: {node_id}")
                if display_name != browse_name:
                    utils.print_info(f"      Display: {display_name}")
                utils.print_info(f"      Class: {self._get_node_class_name(node_class)}")
                
                if data_type:
                    utils.print_info(f"      Type: {data_type}")
                if value is not None:
                    utils.print_info(f"      Value: {value}")
                
                # Add spacing between nodes for readability
                if i < len(nodes):
                    utils.print_info("")
        
        utils.print_info("\n" + "=" * 60)
        
        # Summary
        total_nodes = sum(len(nodes) for nodes in nodes_by_path.values())
        utils.print_success(f"Enumeration complete: {total_nodes} total nodes found across {len(nodes_by_path)} categories")
    
    def _get_node_class_name(self, node_class: str) -> str:
        """Convert numeric node class to human-readable name"""
        node_class_map = {
            '1': 'Object',
            '2': 'Variable', 
            '4': 'Method',
            '8': 'ObjectType',
            '16': 'VariableType',
            '32': 'ReferenceType',
            '64': 'DataType',
            '128': 'View'
        }
        return node_class_map.get(str(node_class), f"Unknown ({node_class})")
    
    def _format_opcua_browse_nodes_result(self, nodes: list):
        """Format OPC UA browse_nodes results in a human-readable way"""
        
        if not nodes:
            utils.print_status("No nodes found")
            return
        
        utils.print_success(f"OPC UA Browse Nodes Results:")
        utils.print_info("=" * 50)
        
        for i, node in enumerate(nodes, 1):
            # Handle both OPCUANode objects and other node types
            if hasattr(node, 'node_id'):
                node_id = node.node_id
                browse_name = node.browse_name
                display_name = node.display_name
                node_class = node.node_class
                data_type = getattr(node, 'data_type', None)
                value = getattr(node, 'value', None)
            else:
                # Fallback for other node representations
                node_id = str(node)
                browse_name = str(node)
                display_name = str(node)
                node_class = "Unknown"
                data_type = None
                value = None
            
            utils.print_info(f"\n🔍 {i:2d}. {browse_name}")
            utils.print_info(f"    ID: {node_id}")
            if display_name != browse_name:
                utils.print_info(f"    Display: {display_name}")
            utils.print_info(f"    Class: {self._get_node_class_name(node_class)}")
            
            if data_type:
                utils.print_info(f"    Type: {data_type}")
            if value is not None:
                utils.print_info(f"    Value: {value}")
        
        utils.print_info("\n" + "=" * 50)
        utils.print_success(f"Browse complete: {len(nodes)} nodes found")
    
    def _format_opcua_server_info_result(self, server_info: dict):
        """Format OPC UA get_server_info results in a human-readable way"""
        
        if not server_info:
            utils.print_status("No server information available")
            return
        
        utils.print_success("OPC UA Server Information:")
        utils.print_info("=" * 50)
        
        info_items = [
            ("🖥️  Server Name", server_info.get('server_name', 'Unknown')),
            ("🌐 Server URI", server_info.get('server_uri', 'Unknown')),
            ("📱 Application URI", server_info.get('application_uri', 'Unknown')),
            ("📦 Product URI", server_info.get('product_uri', 'Unknown')),
            ("🔧 Software Version", server_info.get('software_version', 'Unknown')),
            ("🏗️  Build Number", server_info.get('build_number', 'Unknown')),
            ("📅 Build Date", server_info.get('build_date', 'Unknown'))
        ]
        
        for label, value in info_items:
            if value and value != 'Unknown':
                utils.print_info(f"  {label}: {value}")
            else:
                utils.print_info(f"  {label}: Not available")
        
        utils.print_info("=" * 50)
    
    def _format_opcua_target_info_result(self, target_info: tuple):
        """Format OPC UA get_target_info results in a human-readable way"""
        
        if not target_info or len(target_info) != 6:
            utils.print_status("Invalid target information")
            return
        
        server_name, server_uri, application_uri, product_uri, software_version, build_number = target_info
        
        utils.print_success("OPC UA Target Information:")
        utils.print_info("=" * 50)
        
        info_items = [
            ("🖥️  Server Name", server_name),
            ("🌐 Server URI", server_uri),
            ("📱 Application URI", application_uri),
            ("📦 Product URI", product_uri),
            ("🔧 Software Version", software_version),
            ("🏗️  Build Number", build_number)
        ]
        
        for label, value in info_items:
            if value and value != 'Unknown':
                utils.print_info(f"  {label}: {value}")
            else:
                utils.print_info(f"  {label}: Not available")
        
        utils.print_info("=" * 50) 