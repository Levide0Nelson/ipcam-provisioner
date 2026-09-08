import sys
import os
os.chdir(r'D:\VM_MXLinux_xfce\PartageMXLinux\Projet IP_Automation\camnetpilot')
sys.path.insert(0, r'D:\VM_MXLinux_xfce\PartageMXLinux\Projet IP_Automation\camnetpilot\src')
from camnetpilot.config import load_config
from camnetpilot.discovery import discover_all
from camnetpilot.simulation.demo import demo_config, build_demo_site
import asyncio

async def test():
    cfg = load_config(r'config\siteB_5x.yaml')
    cfg.discovery.active_scan.target_subnets = []
    cfg.discovery.active_scan.max_concurrent = 10
    cfg.discovery.active_scan.scan_timeout = 5.0
    
    network = await build_demo_site(cfg)
    result = await discover_all(cfg, network)
    print(f'Discovered: {len(result)} cameras')
    for c in result.cameras:
        print(f'  {c.mac_address} {c.ip_address} {c.vendor} {c.activation_status.value}')

asyncio.run(test())