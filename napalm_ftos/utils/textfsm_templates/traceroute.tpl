Value TTL (\d+)
Value HOP ([\d\.:a-f]+)
Value PROBES ([\d\.\sms]+)

Start
  ^\s*TTL -> Hop

Hop
  ^\s*(${TTL}\s+)?${HOP}?\s*${PROBES} -> Record
