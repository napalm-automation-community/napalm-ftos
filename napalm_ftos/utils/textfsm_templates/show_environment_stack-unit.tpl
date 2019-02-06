Value UNIT (\d+)
Value TEMPERATURE (\d+)
Value VOLT_STATUS (\w+)
Value TEMP_STATUS (\d+)

Start
  ^\*?\s*${UNIT} .* ${TEMPERATURE}C\s+${VOLT_STATUS}\s+${TEMP_STATUS} -> Record
