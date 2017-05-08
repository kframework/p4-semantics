import argparse
import re

parser = argparse.ArgumentParser()
parser.add_argument('--rules', type=str, nargs=1, default='rules')
parser.add_argument('--covered', type=str, nargs=1, default='covered')
args = parser.parse_args()


rules_file = args.rules
covered_file = args.covered

rules = {}
covered = set()
with open(rules_file) as f:
    for l in f:
        rule = l.strip()
        if rule == "":
            continue
        colon = rule.find(':')
        line = int(rule[0:colon])
        rule = rule[colon+1:]
        rules[line] = rule


with open(covered_file) as f:
    for l in f:
        #print l
        m = re.search(r"Location\((?P<start>\d+)",l)
        if m is None:
            continue
        line =  int(m.group('start'))
        covered.add(line)

uncovered = set(rules.keys()) - covered

print "++++++++++++++++++++++++++++++++++++covered++++++++++++++++++++++++++++++++++++"
for i in sorted(covered):
    print i,":",rules[i]

print "-----------------------------------uncovered-----------------------------------"
for i in sorted(uncovered):
    print i,":",rules[i]


print "___________________________________stats___________________________________"
print "covered:\t", len(covered), "( %.2f %%)" % (float(len(covered))/ len(rules) * 100)
print "uncovered:\t", len(uncovered)
print "total:\t\t", len(rules)