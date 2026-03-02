#  This is an Authentication Log Scanner, it records logs and reports suspicious or anomolous activies and provides statitics to better assist the analyst.
#  to use it open your terminal and enter the python auth_scanner.py auth_test.log code
# How I parse the two-part timestamp, I split each line on whitespace: parts = line.strip().split().
# Everything after the timestamp is parsed as key=value tokens. Tokens without = are skipped
# Why choose collections.counter? Cleaner increments: counter[key] += 1 (exists-or-zero handled automatically).
# Top N built‑ins: counter.most_common(5) directly returns the Top 5 offenders without extra sorting logic.
# I used loggin.warning(..) for visibility when the line is empty, has invalid timestamp etc.
# Empty lines → skipped & counted as malformed
# Missing/invalid timestamps → skipped & counted as malformed
# Malformed key=value tokens → skipped token-by-token; line still usable if any good pairs remain; otherwise malformed
# Missing required fields →
# Missing/invalid status → malformed
# Missing user/ip on FAIL → counted with placeholders ("<unknown_user>", "<unknown_ip>")



# All while never crashing, logging warnings, and accurately reflecting counts in both the JSON and text reports.

# I used Microsoft 365 we meticoulously went through each step together, i asked the question that would make each block of code fall in line with the required functionalty, i learn AI isn't above making horrible mistakes. 
# the hardest was for me to get AI to produce the correct calculations, had to feed it the whole log file to match it with my code.