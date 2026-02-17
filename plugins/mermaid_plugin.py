import os
import subprocess
import json
from plugins.plugin_manager import NexusPlugin

class MermaidVisualizer(NexusPlugin):
    def __init__(self, nexus_core):
        super().__init__(nexus_core)
        self.name = "MermaidVisualizer"
        self.description = "Generates ASCII/SVG diagrams for social media and logs."

    def generate_ascii(self, diagram_text):
        """
        Generates ASCII diagram using beautiful-mermaid via a small Node.js bridge.
        """
        bridge_code = f"""
        const {{ renderMermaidAscii }} = require('beautiful-mermaid');
        try {{
            const ascii = renderMermaidAscii(`{diagram_text}`);
            process.stdout.write(ascii);
        }} catch (e) {{
            process.stderr.write(e.message);
        }}
        """
        try:
            result = subprocess.run(['node', '-e', bridge_code], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
            if result.stderr:
                return f"Bridge Error: {result.stderr}"
            return result.stdout
        except Exception as e:
            return f"Subprocess Error: {e}"

    def run(self, diagram_type="flow", content="A --> B"):
        # Replace semicolons with newlines for Node.js bridge to prevent header parsing errors
        content = content.replace(";", "\n")
        
        if "graph" in content or "sequenceDiagram" in content or "stateDiagram" in content or "flowchart" in content:
            diagram = content
        elif diagram_type == "flow":
            diagram = f"graph TD\n{content}"
        else:
            diagram = content
            
        return self.generate_ascii(diagram)
