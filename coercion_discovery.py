#!/usr/bin/env python3
"""
    _   __                         ____  ____  ______
   / | / /__  _  ____  _______    / __ \\/ __ \\/ ____/
  /  |/ / _ \\| |/_/ / / / ___/   / /_/ / /_/ / /     
 / /|  /  __/>  </ /_/ (__  )   / _, _/ ____/ /___   
/_/ |_/\\___/_/|_|\\__,_/____/   /_/ |_/_/    \\____/   
                                                     
    Nexus Coercion Discovery Module
    XEEA Nexus - Pure Orchestration Stealth Layer
"""

import sys
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import rpcrt
from impacket.dcerpc.v5.rpcrt import DCERPCException

# Suppress impacket logging for clean XEEA output
logging.getLogger("impacket").setLevel(logging.ERROR)

console = Console()

class NexusCoercionDiscovery:
    """
    Discovery module to probe Windows hosts for exposed RPC endpoints 
    susceptible to coercion attacks (MS-RPRN, MS-EFSRPC, MS-FSRVP).
    """
    
    PROTOCOLS = {
        'MS-RPRN': {
            'name': 'Print System (MS-RPRN)',
            'uuid': '12345678-1234-ABCD-EF00-0123456789AB',
            'version': '1.0',
            'pipes': ['\\pipe\\spoolss'],
            'vector_id': 'XEEA-RPRN-01'
        },
        'MS-EFSRPC': {
            'name': 'EFS Remote (MS-EFSRPC)',
            'uuid': 'c681d3ad-9e4b-47a2-be56-4c47411af910',
            'version': '1.0',
            'pipes': ['\\pipe\\efsrpc', '\\pipe\\lsarpc'],
            'vector_id': 'XEEA-EFSR-02'
        },
        'MS-FSRVP': {
            'name': 'File Server VSS (MS-FSRVP)',
            'uuid': 'a8e0653c-2744-4389-9157-370dfb334ae0',
            'version': '1.0',
            'pipes': ['\\pipe\\FssagentRpc'],
            'vector_id': 'XEEA-FSRV-03'
        }
    }

    def __init__(self, targets, username='', password='', domain='', hashes='', port=445):
        """
        Initialize the discovery module.
        :param targets: List of target IPs or hostnames
        """
        if isinstance(targets, str):
            self.targets = [targets]
        else:
            self.targets = targets
            
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.port = port
        
        if hashes:
            try:
                self.lmhash, self.nthash = hashes.split(':')
            except ValueError:
                pass

    def _probe_pipe(self, target, pipe, uuid, version):
        """
        Internal probe to verify if a specific interface can be bound on a pipe.
        """
        string_binding = f'ncacn_np:{target}[{pipe}]'
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_dport(self.port)
        
        # Optional credentials
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            # Perform Stealth Binding - verifying availability without coercion payload
            dce.bind(rpcrt.MSRPC_UUID_PORT(uuid, version))
            dce.disconnect()
            return True, "Success"
        except DCERPCException as e:
            error_msg = str(e)
            if 'abstract_syntax_not_supported' in error_msg:
                return False, "Not Supported"
            elif 'access_denied' in error_msg.lower():
                return False, "Access Denied"
            return False, error_msg
        except Exception as e:
            return False, str(e)

    def run_stealth_scan(self):
        """
        Executes a stealth scan against all configured targets.
        """
        console.print(Panel("[bold cyan]Nexus Discovery[/bold cyan]: Executing Stealth RPC Binding Probe...", border_style="blue"))
        
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            for target in self.targets:
                target_task = progress.add_task(description=f"Probing {target}...", total=len(self.PROTOCOLS))
                
                target_res = {
                    'target': target,
                    'protocols': {}
                }
                
                for proto_key, proto_info in self.PROTOCOLS.items():
                    progress.update(target_task, description=f"Probing {target} -> {proto_info['name']}")
                    
                    is_available = False
                    details = "None Available"
                    
                    for pipe in proto_info['pipes']:
                        success, reason = self._probe_pipe(target, pipe, proto_info['uuid'], proto_info['version'])
                        if success:
                            is_available = True
                            details = pipe
                            break
                        else:
                            details = reason
                            
                    target_res['protocols'][proto_key] = {
                        'status': "[bold green]VULNERABLE[/bold green]" if is_available else "[dim red]NOT FOUND[/dim red]",
                        'details': details,
                        'available': is_available,
                        'vector': proto_info['vector_id']
                    }
                    progress.advance(target_task)
                
                results.append(target_res)

        self._display_results(results)
        return results

    def _display_results(self, results):
        """
        Render discovery results in a pure XEEA Nexus table.
        """
        table = Table(title="Nexus Discovery - Coercion Exposure Map", title_style="bold yellow", border_style="red")
        
        table.add_column("Target Host", style="cyan", no_wrap=True)
        table.add_column("MS-RPRN", justify="center")
        table.add_column("MS-EFSRPC", justify="center")
        table.add_column("MS-FSRVP", justify="center")
        table.add_column("Nexus Vectors", style="dim italic")

        for res in results:
            vectors = []
            for k, v in res['protocols'].items():
                if v['available']:
                    vectors.append(v['vector'])
            
            summary = ", ".join(vectors) if vectors else "No exposure detected"
            
            table.add_row(
                res['target'],
                res['protocols']['MS-RPRN']['status'],
                res['protocols']['MS-EFSRPC']['status'],
                res['protocols']['MS-FSRVP']['status'],
                summary
            )

        console.print("\n")
        console.print(table)
        
        exposed_count = sum(1 for res in results if any(p['available'] for p in res['protocols'].values()))
        if exposed_count > 0:
            console.print(Panel(f"[bold red][!] Discovery complete. {exposed_count} targets show coercion exposure.[/bold red]\n[yellow]Ready for Nexus-Relay escalation cycle.[/yellow]", border_style="red"))
        else:
            console.print("[bold green][+] Discovery complete. No immediate coercion vectors identified with current privileges.[/bold green]")

if __name__ == "__main__":
    # Standalone execution for testing
    if len(sys.argv) < 2:
        console.print("[red]Usage: python3 coercion_discovery.py <target_ip>[/red]")
        sys.exit(1)
        
    discovery = NexusCoercionDiscovery(sys.argv[1])
    discovery.run_stealth_scan()
