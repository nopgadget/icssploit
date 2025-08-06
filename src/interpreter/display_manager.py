import os
from src.config import GITHUB_URL, APP_VERSION, DEFAULT_PROMPT_HOSTNAME


class DisplayManager:
    """Handles all display and output formatting"""
    
    def __init__(self, module_manager, client_manager):
        self.module_manager = module_manager
        self.client_manager = client_manager
        self.prompt_hostname = DEFAULT_PROMPT_HOSTNAME
        self.__parse_prompt()
        self.banner = self._create_banner()

    def __parse_prompt(self):
        """Parse and setup prompt templates"""
        raw_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 > "
        raw_prompt_template = os.getenv("ICSSPLOIT_RAW_PROMPT", raw_prompt_default_template).replace('\\033', '\033')
        self.raw_prompt_template = raw_prompt_template if '{host}' in raw_prompt_template else raw_prompt_default_template

        # Try to use colorama for Windows compatibility if available
        try:
            import colorama
            colorama.init()
            module_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 (\001\033[31m\002{module}\001\033[0m\002) > "
        except ImportError:
            module_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 (\001\033[31m\002{module}\001\033[0m\002) > "
        module_prompt_template = os.getenv("ICSSPLOIT_MODULE_PROMPT", module_prompt_default_template).replace('\\033', '\033')
        self.module_prompt_template = module_prompt_template if all(map(lambda x: x in module_prompt_template, ['{host}', "{module}"])) else module_prompt_default_template

    def _create_banner(self):
        """Create the application banner"""
        # Initialize colorama for Windows compatibility
        try:
            import colorama
            from colorama import Fore, Style
            colorama.init()
            cyan = Fore.CYAN
            reset = Style.RESET_ALL
        except ImportError:
            cyan = '\033[36m'
            reset = '\033[0m'
            
        return r""" 
  _____ _____  _____           _       _ _   
 |_   _/ ____|/ ____|         | |     (_) |  
   | || |    | (___  ___ _ __ | | ___  _| |_ 
   | || |     \___ \/ __| '_ \| |/ _ \| | __|
  _| || |____ ____) \__ \ |_) | | (_) | | |_ 
 |_____\_____|_____/|___/ .__/|_|\___/|_|\__|
                        | |                  
                        |_|                  
                                                                                                              
		   ICS Exploitation Framework


Exploits: {cyan}{exploits_count}{reset} Scanners: {cyan}{scanners_count}{reset} Creds: {cyan}{creds_count}{reset} Clients: {cyan}{clients_count}{reset}

ICS Exploits:
    PLC: {cyan}{plc_exploit_count}{reset}          ICS Switch: {cyan}{ics_switch_exploits_count}{reset}
    Software: {cyan}{ics_software_exploits_count}{reset}

ICS Clients:
    BACnet, Modbus, S7, OPC UA, CIP, WDB2
 """.format(exploits_count=self.module_manager.get_module_count('exploits') + self.module_manager.get_module_count('extra_exploits'),
            scanners_count=self.module_manager.get_module_count('scanners') + self.module_manager.get_module_count('extra_scanners'),
            creds_count=self.module_manager.get_module_count('creds') + self.module_manager.get_module_count('extra_creds'),
            clients_count=len(self.client_manager.get_available_clients()),
            plc_exploit_count=self.module_manager.get_module_count('plcs'),
            ics_switch_exploits_count=self.module_manager.get_module_count('ics_switchs'),
            ics_software_exploits_count=self.module_manager.get_module_count('ics_software'),
            github_url=GITHUB_URL,
            app_version=APP_VERSION,
            cyan=cyan,
            reset=reset
            )

    def get_prompt(self):
        """Get the current prompt string"""
        if self.module_manager.current_module:
            try:
                return self.module_prompt_template.format(host=self.prompt_hostname, module=self.module_manager.module_metadata['name'])
            except (AttributeError, KeyError):
                return self.module_prompt_template.format(host=self.prompt_hostname, module="UnnamedModule")
        else:
            return self.raw_prompt_template.format(host=self.prompt_hostname)

    def get_banner(self):
        """Get the application banner"""
        return self.banner

    def get_global_help(self):
        """Get global help text"""
        return """Global commands:
    help                        Print this help menu
    use <module>                Select a module for usage
    exec <shell command> <args> Execute a command in a shell
    search <search term>        Search for appropriate module
    client <command>            Client management commands
    exit                        Exit icssploit"""

    def get_module_help(self):
        """Get module help text"""
        return """Module commands:
    run                                 Run the selected module with the given options
    back                                De-select the current module
    set <option name> <option value>    Set an option for the selected module
    setg <option name> <option value>   Set an option for all of the modules
    unsetg <option name>                Unset option that was set globally
    options                             Show options for the selected module
    show [info|options|devices]         Print information, options, or target devices for a module
    check                               Check if a given target is vulnerable to a selected module's exploit"""

    def get_show_sub_commands(self):
        """Get available show sub-commands"""
        return ('info', 'options', 'devices', 'all', 'creds', 'exploits', 'scanners') 