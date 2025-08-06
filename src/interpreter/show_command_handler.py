from src import utils


class ShowCommandHandler:
    """Handles all show-related commands"""
    
    def __init__(self, module_manager):
        self.module_manager = module_manager

    def handle_show_command(self, args):
        """Handle show command with sub-commands"""
        sub_command = args[0]
        try:
            method = getattr(self, "_show_{}".format(sub_command))
            # Call the method - if it's module_required and no module is loaded, 
            # the decorator will handle the error message
            method(*args, **{})
        except AttributeError:
            utils.print_error("Unknown 'show' sub-command '{}'. "
                              "What do you want to show?\n"
                              "Possible choices are: {}".format(sub_command, self.get_show_sub_commands()))

    def get_show_sub_commands(self):
        """Get available show sub-commands"""
        return ('info', 'options', 'devices', 'all', 'creds', 'exploits', 'scanners')

    @utils.module_required
    def _show_info(self, *args, **kwargs):
        """Show module information"""
        utils.pprint_dict_in_order(
            self.module_manager.module_metadata,
            ("name", "description", "devices", "authors", "references"),
        )
        utils.print_info()

    @utils.module_required
    def _show_options(self, *args, **kwargs):
        """Show module options"""
        target_opts = ['target', 'port']
        module_opts = [opt for opt in self.module_manager.current_module.options if opt not in target_opts]
        headers = ("Name", "Current settings", "Description")

        utils.print_info('\nTarget options:')
        utils.print_table(headers, *self._get_opts(*target_opts))

        if module_opts:
            utils.print_info('\nModule options:')
            utils.print_table(headers, *self._get_opts(*module_opts))

        utils.print_info()

    @utils.module_required
    def _show_devices(self, *args, **kwargs):
        """Show target devices"""
        try:
            devices = self.module_manager.current_module.__class__.__info__['devices']

            utils.print_info("\nTarget devices:")
            i = 0
            for device in devices:
                if isinstance(device, dict):
                    utils.print_info("   {} - {}".format(i, device['name']))
                else:
                    utils.print_info("   {} - {}".format(i, device))
                i += 1
            utils.print_info()
        except KeyError:
            utils.print_info("\nTarget devices are not defined")

    def _show_all(self, *args, **kwargs):
        """Show all modules"""
        self.__show_modules()

    def _show_scanners(self, *args, **kwargs):
        """Show scanner modules"""
        self.__show_modules('scanners')

    def _show_exploits(self, *args, **kwargs):
        """Show exploit modules"""
        self.__show_modules('exploits')

    def _show_creds(self, *args, **kwargs):
        """Show credential modules"""
        self.__show_modules('creds')

    def __show_modules(self, root=''):
        """Show modules filtered by root"""
        for module in [module for module in self.module_manager.get_all_modules() if module.startswith(root)]:
            utils.print_info(module.replace('.', '/'))

    def _get_opts(self, *args):
        """Generator returning module's Option attributes (option_name, option_value, option_description)"""
        for opt_key in args:
            try:
                # Try to get description from exploit_attributes first (metaclass approach)
                opt_description = self.module_manager.current_module.exploit_attributes[opt_key]
                opt_value = getattr(self.module_manager.current_module, opt_key)
                yield opt_key, opt_value, opt_description
            except (KeyError, AttributeError):
                # Fallback: get description directly from the Option instance
                try:
                    opt_value = getattr(self.module_manager.current_module, opt_key)
                    # Get the Option instance from the class using __dict__ to avoid triggering __get__
                    option_instance = self.module_manager.current_module.__class__.__dict__.get(opt_key)
                    if option_instance and hasattr(option_instance, 'description'):
                        opt_description = option_instance.description
                    else:
                        opt_description = "No description available"
                    yield opt_key, opt_value, opt_description
                except (AttributeError, KeyError):
                    # If we can't get the description, use a default
                    opt_description = "No description available"
                    opt_value = getattr(self.module_manager.current_module, opt_key, "Not set")
                    yield opt_key, opt_value, opt_description 