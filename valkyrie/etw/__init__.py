"""Real-time ETW-backed endpoint sensors.

Hosts a sensor framework (framework.py) and ETW/event-log-backed sensors that
emit the shared valkyrie.telemetry.TelemetryEvent into the SAME EventBus -> EDR
pipeline as the polling collectors. No parallel pipeline, no new store.
"""

from .framework import Sensor, SensorManager
from .powershell import PowerShellSensor, classify_powershell
from .wmi import WmiActivitySensor, classify_wmi
from .sysmon import SysmonSensor, classify_sysmon
from .native_process import NativeProcessSensor, map_4688
from .wineventlog import ChannelReader, parse_event_xml

__all__ = [
    "Sensor", "SensorManager",
    "PowerShellSensor", "classify_powershell",
    "WmiActivitySensor", "classify_wmi",
    "SysmonSensor", "classify_sysmon",
    "NativeProcessSensor", "map_4688",
    "ChannelReader", "parse_event_xml",
]
