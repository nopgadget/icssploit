import itertools
from src import utils


class CompletionEngine:
    """Handles tab completion and command suggestions"""
    
    def __init__(self, module_manager):
        self.module_manager = module_manager
        self.global_commands = sorted(['use ', 'exec ', 'help', 'exit', 'show ', 'search ', 'client '])
        self.module_commands = ['run', 'back', 'set ', 'setg ', 'check', 'options']
        self.module_commands.extend(self.global_commands)
        self.module_commands.sort()

    def available_modules_completion(self, text):
        """Looking for tab completion hints using setup.py entry_points.

        May need optimization in the future!

        :param text: argument of 'use' command
        :return: list of tab completion hints
        """
        text = utils.pythonize_path(text)
        all_possible_matches = filter(lambda x: x.startswith(text), self.module_manager.get_all_modules())
        matches = set()
        for match in all_possible_matches:
            head, sep, tail = match[len(text):].partition('.')
            if not tail:
                sep = ""
            matches.add("".join((text, head, sep)))
        return list(map(utils.humanize_path, matches))  # humanize output, replace dots to forward slashes

    def suggested_commands(self):
        """Entry point for intelligent tab completion.

        Based on state of interpreter this method will return intelligent suggestions.

        :return: list of most accurate command suggestions
        """
        from src.exploits import GLOBAL_OPTS
        
        if self.module_manager.current_module and GLOBAL_OPTS:
            return sorted(itertools.chain(self.module_commands, ('unsetg ',)))
        elif self.module_manager.current_module:
            custom_commands = [command.rsplit("_").pop() for command in dir(self.module_manager.current_module)
                               if command.startswith("command_")]
            self.module_commands.extend(custom_commands)
            return self.module_commands
        else:
            return self.global_commands

    @utils.stop_after(2)
    def complete_use(self, text, *args, **kwargs):
        """Enhanced tab completion for the 'use' command.
        
        Provides intelligent suggestions:
        - When no text: shows main categories (scanners, exploits, creds)
        - When partial text: shows matching categories or modules
        - When specific prefix: shows relevant modules
        """
        if not text:
            # Show main categories when no text is provided
            categories = ['scanners/', 'exploits/', 'creds/']
            extra_dirs = self.module_manager.get_extra_modules_dirs()
            if extra_dirs:
                return categories + extra_dirs
            else:
                return categories
        
        # Convert text to lowercase for case-insensitive matching
        text_lower = text.lower()
        
        # Get all available modules
        all_modules = self.module_manager.get_all_modules()
        
        # Filter modules that start with the text
        matching_modules = []
        for module in all_modules:
            # Convert module path to human-readable format
            human_path = utils.humanize_path(module)
            if human_path.lower().startswith(text_lower):
                matching_modules.append(human_path)
        
        # If we have exact category matches, prioritize them
        category_matches = []
        for module in matching_modules:
            if '/' in module and module.split('/')[0].lower().startswith(text_lower):
                category = module.split('/')[0] + '/'
                if category not in category_matches:
                    category_matches.append(category)
        
        # If we have category matches and text is short, show categories first
        if len(text) <= 3 and category_matches:
            return category_matches
        
        # Return matching modules, sorted for better UX
        return sorted(matching_modules)

    @utils.stop_after(2)
    def complete_set(self, text, *args, **kwargs):
        """Complete set command with module options"""
        if not self.module_manager.current_module:
            return []
        
        if text:
            return [' '.join((attr, "")) for attr in self.module_manager.current_module.options if attr.startswith(text)]
        else:
            return self.module_manager.current_module.options

    @utils.stop_after(2)
    def complete_setg(self, text, *args, **kwargs):
        """Complete setg command with module options"""
        return self.complete_set(text, *args, **kwargs)

    @utils.stop_after(2)
    def complete_unsetg(self, text, *args, **kwargs):
        """Complete unsetg command with global options"""
        from src.exploits import GLOBAL_OPTS
        
        if text:
            return [' '.join((attr, "")) for attr in GLOBAL_OPTS.keys() if attr.startswith(text)]
        else:
            return GLOBAL_OPTS.keys()

    @utils.stop_after(2)
    def complete_show(self, text, *args, **kwargs):
        """Complete show command with sub-commands"""
        show_sub_commands = ('info', 'options', 'devices', 'all', 'creds', 'exploits', 'scanners')
        
        if text:
            return [command for command in show_sub_commands if command.startswith(text)]
        else:
            return show_sub_commands

    @utils.stop_after(2)
    def complete_search(self, text, *args, **kwargs):
        """Provide tab completion for search terms based on common keywords"""
        if not text:
            # Common search terms when no text is provided
            return ['plc', 'siemens', 'schneider', 'modbus', 's7', 'profinet', 'ethernet', 'tcp', 'udp']
        
        # Get unique keywords from module names
        keywords = set()
        for module in self.module_manager.get_all_modules():
            human_path = utils.humanize_path(module)
            # Extract meaningful keywords from module paths
            parts = human_path.lower().split('/')
            for part in parts:
                if len(part) > 2:  # Only meaningful keywords
                    keywords.add(part)
        
        # Filter keywords that start with the text
        matching_keywords = [kw for kw in keywords if kw.startswith(text.lower())]
        return sorted(matching_keywords)

    @utils.stop_after(2)
    def complete_client(self, text, *args, **kwargs):
        """Provide tab completion for client commands"""
        # Get the full command line to determine context
        import readline
        line = readline.get_line_buffer()
        parts = line.split()
        
        if len(parts) == 1:  # Just "client"
            sub_commands = ['create', 'list', 'use', 'connect', 'disconnect', 'remove', 'info', 'help', 'types', 'call']
            return [cmd for cmd in sub_commands if cmd.startswith(text)]
        
        elif len(parts) == 2:  # "client <subcommand>"
            sub_command = parts[1]
            if sub_command in ['create']:
                # Complete client types for create
                from src.client_manager import ClientManager
                client_manager = ClientManager()
                client_types = client_manager.get_available_clients()
                return [ct for ct in client_types if ct.startswith(text)]
            elif sub_command in ['use', 'connect', 'disconnect', 'remove', 'info']:
                # Complete client names
                from src.client_manager import ClientManager
                client_manager = ClientManager()
                client_names = list(client_manager.list_clients().keys())
                return [name for name in client_names if name.startswith(text)]
            elif sub_command in ['help']:
                # Complete client types for help
                from src.client_manager import ClientManager
                client_manager = ClientManager()
                client_types = client_manager.get_available_clients()
                return [ct for ct in client_types if ct.startswith(text)]
            elif sub_command in ['call']:
                # Complete client names for call
                from src.client_manager import ClientManager
                client_manager = ClientManager()
                client_names = list(client_manager.list_clients().keys())
                return [name for name in client_names if name.startswith(text)]
            else:
                return []
        
        elif len(parts) == 3 and parts[1] == 'call':  # "client call <name>"
            # Complete method names for the specified client
            client_name = parts[2]
            from src.client_manager import ClientManager
            client_manager = ClientManager()
            client = client_manager.get_client(client_name)
            if client:
                methods = [method for method in dir(client) 
                          if not method.startswith('_') and callable(getattr(client, method))]
                return [method for method in methods if method.startswith(text)]
            return []
        
        else:
            return [] 