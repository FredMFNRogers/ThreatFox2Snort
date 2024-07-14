# ThreatFox2Snort
Python script created to generate Snort rules from IOCs reported by ThreatFox during the past 48 hours. This script excludes IOCs containing dotted quads for accuracy and redundancy.

# Usage Options:
  - **--config CONFIG**       (Path to configuration file)
    
  - **-h, --help**            (show this help message and exit)

  - **-s SID_START, --sid_start** SID_START
                        (Starting SID for rules)
  - **-o OUTPUT, --output OUTPUT**
                        (Output file for Snort rules)
