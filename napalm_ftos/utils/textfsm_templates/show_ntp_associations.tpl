#remote       vrf-Id     ref clock     st when poll reach   delay   offset    disp
#====================================================================================
#*172.14.14.1       0   172.14.14.1      3    6   16  377     0.37    1.769    0.55
#* master (synced), # master (unsynced), + selected, - candidate
Value TYPE ([\*#\+\-]?)
Value REMOTE ([a-f0-9\.:]+)
Value REFERENCEID ([a-f0-9\.:]+)
Value STRATUM (\d+)
Value WHEN (\d+)
Value HOSTPOLL (\d+)
Value REACHABILITY (\d+)
Value DELAY ([0-9\.]+)
Value OFFSET ([0-9\.]+)
Value JITTER ([0-9\.]+)


Start
  ^\s*${TYPE}${REMOTE}\s+\d+\s+${REFERENCEID}\s+${STRATUM}\s+${WHEN}\s+${HOSTPOLL}\s+${REACHABILITY}\s+${DELAY}\s+${OFFSET}\s+${JITTER} -> Record
