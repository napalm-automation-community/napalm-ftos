Value VLAN (\d+)
Value MAC (([a-f0-9]{2}:){5}[a-f0-9]{2})
Value STATIC (\w+)
Value INTERFACE (\w+ \d+(\/\d+)?)
Value ACTIVE (\w+)

Start
  ^\s*${VLAN}\s+${MAC}\s+${STATIC}(\s*\(\w\))?\s+${INTERFACE}\s+${ACTIVE} -> Record
