import os
import sys
from collections import Counter

from src import utils
from src.exceptions import icssploitException


class ModuleManager:
    """Manages module loading, selection, and metadata"""
    
    def __init__(self, extra_package_path=None):
        self.current_module = None
        self.extra_modules_dir = None
        self.extra_modules_dirs = None
        self.extra_modules = []
        self.extra_package_path = extra_package_path
        self.import_extra_package()
        self.modules = utils.index_modules()
        self.modules += self.extra_modules
        self.modules_count = Counter()
        [self.modules_count.update(module.split('.')) for module in self.modules]
        self.main_modules_dirs = [module for module in os.listdir(utils.MODULES_DIR) if not module.startswith("__")]

    def import_extra_package(self):
        """Import extra modules from external package path"""
        if self.extra_package_path:
            extra_modules_dir = os.path.join(self.extra_package_path, "extra_modules")
            if os.path.isdir(extra_modules_dir):
                self.extra_modules_dir = extra_modules_dir
                self.extra_modules_dirs = [module for module in os.listdir(self.extra_modules_dir) if
                                           not module.startswith("__")]
                self.extra_modules = utils.index_extra_modules(modules_directory=self.extra_modules_dir)
                print("extra_modules_dir:%s" % self.extra_modules_dir)
                sys.path.append(self.extra_package_path)
                sys.path.append(self.extra_modules_dir)
        else:
            return

    def use_module(self, module_path):
        """Load and select a module"""
        if module_path.startswith("extra_"):
            module_path = utils.pythonize_path(module_path)
        else:
            module_path = utils.pythonize_path(module_path)
            module_path = '.'.join(('src', 'modules', module_path))
        try:
            self.current_module = utils.import_exploit(module_path)()
        except icssploitException as err:
            utils.print_error(str(err))

    def back(self):
        """Deselect current module"""
        self.current_module = None

    @property
    def module_metadata(self):
        """Get metadata of current module"""
        return getattr(self.current_module.__class__, "__info__")

    def get_modules_by_category(self, category):
        """Get modules filtered by category"""
        return [module for module in self.modules if module.startswith(category)]

    def get_module_count(self, category):
        """Get count of modules in a category"""
        return self.modules_count.get(category, 0)

    def get_all_modules(self):
        """Get all available modules"""
        return self.modules

    def get_extra_modules_dirs(self):
        """Get extra modules directories"""
        return self.extra_modules_dirs or []

    def get_main_modules_dirs(self):
        """Get main modules directories"""
        return self.main_modules_dirs 