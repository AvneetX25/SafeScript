# Save the script to a temp file

import json

with open('evaluation/pygoat_results.json', 'r') as f:
    data = json.load(f)

for report in data:
    findings = report.get('results', [])
    if not findings:
        continue
    filename = report['file'].replace('\\\\', '/').split('/')[-1]
    print('FILE: ' + filename)
    for f in findings:
        sev = f.get('severity', 'UNKNOWN')
        func = f.get('function', '?')
        line = f.get('start_line', '?')
        rule = f.get('primary_rule', '?')
        print('  [' + sev + '] ' + func + ' line ' + str(line) + ' rule=' + rule)
    

