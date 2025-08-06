from src import utils


class SearchEngine:
    """Handles search functionality"""
    
    def __init__(self, module_manager):
        self.module_manager = module_manager

    def search(self, keyword):
        """Search for modules containing the keyword"""
        if not keyword:
            utils.print_error("Please specify search keyword. e.g. 'search plc'")
            return

        for module in self.module_manager.get_all_modules():
            if keyword.lower() in module.lower():
                module = utils.humanize_path(module)
                utils.print_info(
                    "{}\033[31m{}\033[0m{}".format(*module.partition(keyword))
                )

    def get_search_completions(self, text):
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