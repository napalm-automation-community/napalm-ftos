#
#Protocol    Address         Age(min)  Hardware Address    Interface      VLAN             CPU
#---------------------------------------------------------------------------------------------
#Internet    172.14.14.1           0   e4:8d:8c:04:33:49   Ma 0/0          -               CP
#Internet    172.14.14.6          70   f8:b1:56:4c:66:f0   Ma 0/0          -               CP
Value IP ([a-f0-9\.:]+)
Value AGE (\d+)
Value MAC ([a-fA-F0-9:]+)
Value INTERFACE (\w+ \d(/\d+)?)

Start
  ^\s*[^\s]+\s+${IP}\s+${AGE}\s+${MAC}\s+${INTERFACE}\s+ -> Record
