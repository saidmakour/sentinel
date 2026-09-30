from sentinel.plugins.go.plugin import GoPlugin
from sentinel.plugins.java.plugin import JavaPlugin
from sentinel.plugins.node.plugin import NodePlugin
from sentinel.plugins.php.plugin import PHPPlugin
from sentinel.plugins.python.plugin import PythonPlugin
from sentinel.plugins.registry import PluginRegistry
from sentinel.plugins.ruby.plugin import RubyPlugin


def create_plugin_registry() -> PluginRegistry:
    return PluginRegistry(
        [
            PythonPlugin(),
            NodePlugin(),
            PHPPlugin(),
            JavaPlugin(),
            GoPlugin(),
            RubyPlugin(),
        ]
    )
