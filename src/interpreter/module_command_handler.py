import traceback
import sys
from src import utils
from src.exploits import GLOBAL_OPTS


class ModuleCommandHandler:
    """Handles module-specific commands"""
    
    def __init__(self, module_manager):
        self.module_manager = module_manager

    @utils.module_required
    def run(self, *args, **kwargs):
        """Run the current module"""
        utils.print_status("Running module...")
        try:
            self.module_manager.current_module.run()
        except KeyboardInterrupt:
            utils.print_info()
            utils.print_error("Operation cancelled by user")
        except:
            utils.print_error(traceback.format_exc(sys.exc_info()))

    def exploit(self, *args, **kwargs):
        """Alias for run command"""
        self.run(*args, **kwargs)

    @utils.module_required
    def set(self, *args, **kwargs):
        """Set a module option"""
        key, _, value = args[0].partition(' ')
        if key in self.module_manager.current_module.options:
            setattr(self.module_manager.current_module, key, value)
            if kwargs.get("glob", False):
                GLOBAL_OPTS[key] = value
            utils.print_success({key: value})
        else:
            utils.print_error("You can't set option '{}'.\n"
                              "Available options: {}".format(key, self.module_manager.current_module.options))

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

    @utils.module_required
    def check(self, *args, **kwargs):
        """Check if target is vulnerable"""
        try:
            result = self.module_manager.current_module.check()
        except Exception as error:
            utils.print_error(error)
        else:
            if result is True:
                utils.print_success("Target is vulnerable")
            elif result is False:
                utils.print_error("Target is not vulnerable")
            else:
                utils.print_status("Target could not be verified")

    def options(self, *args, **kwargs):
        """Show module options"""
        self._show_options(*args, **kwargs)

    def get_opts(self, *args):
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

    def _show_options(self, *args, **kwargs):
        """Show module options in a formatted table"""
        target_opts = ['target', 'port']
        module_opts = [opt for opt in self.module_manager.current_module.options if opt not in target_opts]
        headers = ("Name", "Current settings", "Description")

        utils.print_info('\nTarget options:')
        utils.print_table(headers, *self.get_opts(*target_opts))

        if module_opts:
            utils.print_info('\nModule options:')
            utils.print_table(headers, *self.get_opts(*module_opts))

        utils.print_info() 