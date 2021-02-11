#!/usr/bin/env python3
import sys
import re

def main(argv):
	if len(sys.argv) == 3:
		if check_ip_address(sys.argv[1]) is False:
			print(f"Invalid IP address: {sys.argv[1]}")
			sys.exit()
		if check_ip_address(sys.argv[2]) is False:
			print(f"Invalid IP address: {sys.argv[2]}")
			sys.exit()

		quads = sys.argv[1].split('.')
		mask_bit = get_cidr_ip_range(sys.argv[1], sys.argv[2])
		print(f"{quads[0]}.{quads[1]}.{quads[2]}.0/{mask_bit}")

	else:
		usage()

def usage():
	print(f"Convert an IPv4 address range to CIDR notation, e.g: {sys.argv[0]} 1.2.3.0 1.2.5.255")

def check_ip_address(ip):
    ip_regex = r'^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}'
    ip_regex = ip_regex + r'([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    ip_address_regex = re.compile(ip_regex)
    match = ip_address_regex.match(ip)

    if match is not None:
        return True
    return False

def get_cidr_ip_range(ip_address_1, ip_address_2):
    range_dictionary = {0: 0, 1: 1, 3: 2, 7: 3, 15: 4, 31: 5, 63: 6, 127: 7, 255: 8}
    cl = [0, 0, 0, 0]

    address_1, address_2 = split_ip_addresses(ip_address_1, ip_address_2)

    for i in range(len(cl)):
        if difference_list(address_2, address_1, i) in range_dictionary:
            cl[i] = 8 - range_dictionary[difference_list(address_2, address_1, i)]
        else:
            print('Error in converting to CIDR notation')
            sys.exit()

    mask_bit = sum_list(cl)
    return mask_bit

def sum_list(list):
    s = 0
    for v in list:
        s += v
    return s

def difference_list(la, lb, idx):
    if not len(la) == len(lb):
        print('Invalid list size')
        return None

    if len(la) < idx:
        print('Invalid index')
        return None

    return int(la[idx]) - int(lb[idx])

def split_ip_addresses(ip_address_1, ip_address_2):
    li_1 = ip_address_1.split('.')
    li_2 = ip_address_2.split('.')

    return (li_1, li_2)

# If this file is executed, __name__ is set to __main__ and main() executes.
# If this file is imported, lines below the if statement are not executed.
if __name__ == '__main__':
    main(sys.argv[1:])
