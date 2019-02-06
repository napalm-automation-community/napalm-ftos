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
