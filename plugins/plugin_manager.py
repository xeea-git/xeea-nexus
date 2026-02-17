#!/usr/bin/env python3
"""
    XEEA Nexus - Plugin Interface
    Standard for extending Nexus with external tools and modules.
"""

class NexusPlugin:
    def __init__(self, nexus_core):
        self.nexus = nexus_core
        self.name = "BasePlugin"
        self.description = "Base Nexus Plugin"

    def run(self, **kwargs):
        raise NotImplementedError("Plugins must implement run()")

class PluginManager:
    def __init__(self, nexus_core):
        self.nexus = nexus_core
        self.plugins = {}

    def load_plugin(self, plugin_class):
        plugin = plugin_class(self.nexus)
        self.plugins[plugin.name] = plugin
        return plugin

    def execute(self, plugin_name, **kwargs):
        if plugin_name in self.plugins:
            return self.plugins[plugin_name].run(**kwargs)
        return None
