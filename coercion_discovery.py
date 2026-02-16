#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    _   __                         ____  ____  ______
   / | / /__  _  ____  _______    / __ \\/ __ \\/ ____/
  /  |/ / _ \\| |/_/ / / / ___/   / /_/ / /_/ / /     
 / /|  /  __/>  </ /_/ (__  )   / _, _/ ____/ /___   
/_/ |_/\\___/_/|_|\\__,_/____/   /_/ |_/_/    \\____/   
                                                     
    XEEA Nexus - Coercion Discovery Module
    Module: coercion_discovery.py
    Purpose: Probe for vulnerable RPC endpoints (MS-RPRN, MS-EFSRPC, MS-FSRVP)
    Branding: PURE XEEA
"""

import sys
import logging
from impacket.dcerpc.v5 import transport, rpcrt
from impacket.uuid import uuidtostring, string_to_bin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Suppress impacket logging
logging.getLogger('impacket').setLevel(logging.ERROR)

class NexusCoercionDiscovery:
    """
    Modular class for discovering coercion-vulnerable RPC endpoints on Windows hosts.
    Integrates with XEEA Nexus Core.
    """
    
    ENDPOINTS = {
        'MS-RPRN': {
            'uuid': '12345678-1234-ABCD-EF00-0123456789AB',
            'pipes': [r'\pipe\spoolss'],
            'description': 'Print System Remote Protocol'
        },
        'MS-EFSRPC': {
            'uuid': 'c681d588-4288-409d-8302-601401344446',
            'pipes': [r'\pipe\efsrpc', r'\pipe\lsarpc'],
            'description': 'Encrypting File System Remote (EFSRPC)'
        },
        'MS-FSRVP': {
            'uuid': 'a074f0b6-333d-47a2-9ca0-c3d446ec2a46',
            'pipes': [r'\pipe\FssagentRpc'],
            'description': 'File Server Remote VSS Protocol'
        }
    }

    def __init__(self, target_list, verbose=False):
        self.console = Console()
        if isinstance(target_list, str):
            self.targets = [target_list]
        else:
            self.targets = target_list
        self.verbose = verbose
        self.results = []

    def _check_binding(self, target, pipe, interface_uuid):
        """
        Attempts to bind to a specific pipe and interface.
        Stealth mode: Only binding, no payload.
        """
        string_binding = r'ncacn_np:%s[%s]' % (target, pipe)
        try:
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            # Use anonymous/null session if possible, or guest
            rpc_transport.set_credentials('', '', '', '', '')
            rpc_transport.set_connect_timeout(5)
            
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(string_to_bin(interface_uuid))
            dce.disconnect()
            return True
        except Exception:
            return False

    def run_stealth_scan(self):
        """
        Executes the stealth discovery scan across all targets.
        """
        self.console.print("[bold cyan][*] Starting XEEA Nexus Stealth Coercion Discovery...[/bold cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            for target in self.targets:
                target_task = progress.add_task(f"Scanning {target}...", total=len(self.ENDPOINTS))
                target_results = {'target': target, 'vulnerabilities': {}}
                
                for protocol, data in self.ENDPOINTS.items():
                    is_vulnerable = False
                    for pipe in data['pipes']:
                        if self._check_binding(target, pipe, data['uuid']):
                            is_vulnerable = True
                            break
                    
                    target_results['vulnerabilities'][protocol] = is_vulnerable
                    progress.advance(target_task)
                
                self.results.append(target_results)

        self._display_results()

    def _display_results(self):
        """
        Displays scan results in a Rich table.
        """
        table = Table(title="XEEA Nexus - Coercion Discovery Results", border_style="red", header_style="bold magenta")
        table.add_column("Target Host", style="cyan")
        table.add_column("MS-RPRN", justify="center")
        table.add_column("MS-EFSRPC", justify="center")
        table.add_column("MS-FSRVP", justify="center")
        table.add_column("Status", justify="right")

        for res in self.results:
            vulns = res['vulnerabilities']
            
            # Formatting status with symbols
            rprn = "[bold green]EXPOSED[/bold green]" if vulns['MS-RPRN'] else "[dim]Closed[/dim]"
            efs = "[bold green]EXPOSED[/bold green]" if vulns['MS-EFSRPC'] else "[dim]Closed[/dim]"
            fsrvp = "[bold green]EXPOSED[/bold green]" if vulns['MS-FSRVP'] else "[dim]Closed[/dim]"
            
            any_exposed = any(vulns.values())
            overall_status = "[bold red]VULNERABLE[/bold red]" if any_exposed else "[bold blue]SECURE[/bold blue]"
            
            table.add_row(res['target'], rprn, efs, fsrvp, overall_status)

        self.console.print("\n")
        self.console.print(table)
        
        if any(any(r['vulnerabilities'].values()) for r in self.results):
            self.console.print("\n[bold yellow][!] High-value coercion paths discovered. Proceed with XEEA Relay pipeline.[/bold yellow]")
        else:
            self.console.print("\n[dim][*] No exposed coercion endpoints detected on the specified targets.[/dim]")

if __name__ == "__main__":
    # Standalone execution test
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    discovery = NexusCoercionDiscovery(target)
    discovery.run_stealth_scan()
