# plugin_manager.py - Manages all forensic plugins

import os
import sys
import importlib.util
import importlib
from abc import ABC, abstractmethod

# Add plugins directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

class ForensicPlugin(ABC):
    """
    Abstract base class for all forensic plugins.
    Every tool must inherit from this class.
    """
    
    @property
    @abstractmethod
    def name(self):
        """Return the display name of the tool"""
        pass
    
    @property
    @abstractmethod
    def description(self):
        """Return a brief description of what the tool does"""
        pass
    
    @property
    @abstractmethod
    def version(self):
        """Return plugin version"""
        pass
    
    @abstractmethod
    def supported_types(self):
        """
        Return list of supported file types/extensions
        Example: ['.jpg', '.jpeg', '.tiff']
        """
        pass
    
    @abstractmethod
    def analyze(self, file_path, output_dir=None, **kwargs):
        """
        Main analysis method.
        
        Args:
            file_path: Path to the evidence file
            output_dir: Where to save results (optional)
            **kwargs: Additional parameters specific to the tool
        
        Returns:
            dict: Analysis results
        """
        pass
    
    def validate_file(self, file_path):
        """Check if file exists and is supported"""
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.supported_types():
            return False, f"Unsupported file type: {ext}"
        
        return True, "Valid"

# Ensure project root is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
class PluginManager:
    """Manages loading and running of all plugins"""
    
    def __init__(self):
        self.plugins = {}
        self.load_all_plugins()
    
    def load_all_plugins(self):
        """Discover and load all plugins from plugins directory"""
        plugins_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'plugins')
        print(f"Loading plugins from: {plugins_dir}")

        for root, dirs, files in os.walk(plugins_dir):
            for file in files:
                if file.endswith('_plugin.py'):
                    full_path = os.path.join(root, file)
                    spec = importlib.util.spec_from_file_location(file[:-3], full_path)
                    module = importlib.util.module_from_spec(spec)
                    try:
                        spec.loader.exec_module(module)
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (isinstance(attr, type) and
                                attr.__name__ != 'ForensicPlugin' and
                                hasattr(attr, 'analyze') and
                                hasattr(attr, 'name')):
                                try:
                                    plugin = attr()
                                    self.plugins[plugin.name] = plugin
                                    print(f"  Loaded: {plugin.name} v{plugin.version}")
                                except Exception as e:
                                    print(f"  Failed to instantiate {attr_name}: {e}")
                    except Exception as e:
                        import traceback
                        print(f"  Failed to load {file}: {e}")
                        traceback.print_exc()

        print(f"Total plugins loaded: {len(self.plugins)}")
    
    def get_plugin(self, name):
        """Get a specific plugin by name"""
        return self.plugins.get(name)
    
    def list_plugins(self):
        """Return information about all available plugins"""
        info = {}
        for name, plugin in self.plugins.items():
            info[name] = {
                'description': plugin.description,
                'version': plugin.version,
                'supported_types': plugin.supported_types()
            }
        return info
    
    def run_analysis(self, plugin_name, file_path, **kwargs):
        """Run a specific plugin on a file"""
        plugin = self.get_plugin(plugin_name)
        
        if not plugin:
            return {
                'success': False,
                'error': f'Plugin "{plugin_name}" not found'
            }
        
        # Validate file
        valid, message = plugin.validate_file(file_path)
        if not valid:
            return {
                'success': False,
                'error': message
            }
        
        # Run analysis
        try:
            results = plugin.analyze(file_path, **kwargs)
            return {
                'success': True,
                'plugin': plugin_name,
                'results': results
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }