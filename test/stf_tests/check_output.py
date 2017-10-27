import sys
import re

output = sys.argv[1]
expected = sys.argv[2]

out_packets = []
expected_packets = []

def process_top(l):
    while len(l) > 0:
        assert l[0] == 'ListItem'
        packet, l = process_packet(l[2:])
        out_packets.append(packet)

def process_packet(l):
    assert l[0] == '$packet'
    packet_data,l = process_packet_data(l[2:])
    port = l[0]
    return (packet_data, port), l[3:]

def process_packet_data(l):
    ret = ""
    while l[0] == 'ListItem':
        val = process_val(l[2:10])
        l = l[11:]
        ret += val
    return ret, l[1:]

def process_val(l):
    n = int(l[2])
    w = int(l[4])
    s = l[6]
    assert s == "false"
    return ("{:0%db}" % w).format(n)


with open(output,'r') as f:
    content = f.read()
    m = re.search(r"<out> (?P<out>.*) </out>", content)
    out = m.group('out')
    process_top(out.split())

with open(expected,'r') as f:
    for l in f:
        expected_packets.append(l.split())

print "output"
print "\n".join(map(str,out_packets))
print "expected"
print "\n".join(map(str,expected_packets))

err = False
if len(out_packets) < len(expected_packets):
    print "Error: fewer packets than expected (expected at least %d, got %d)" % (len(expected_packets), len(out_packets))
    err = True

for i,e in enumerate(expected_packets):
    print "checking packet",i
    o = out_packets[i]
    if o[1] != e[1]:
        print "Error: unexpected port number (expected %s, got %s)" % (e[1], o[1])
        err = True
    po,pe = o[0],e[0]
    if len(po) < len(pe):
        print "Error: packet shorter than expected:  (expected at least %d, got %d)" % (len(pe), len(po))
        err = True
    for j,b in enumerate(pe):
        if b != po[j] and b != '*':
            print "Error: unexpected bit in packet at index %d, (expected %s, got %s)" % (j,b,po[j])
            err = True
            break

sys.exit(1 if err else 0)
