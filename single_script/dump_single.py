import os
import re
import ida_segment
import idc
import ida_bytes
import json

dumps_files = []

def dump_segment_to_file(seg_start, seg_end, filename):
    """
    Dump segment data to file
    """
    try:
        seg_size = seg_end - seg_start
        if seg_size <= 0:
            print(f"[-] Invalid segment size: {seg_size}")
            return False
        
        if seg_size > 0x4000000:
            print(f"[!] To Big segment size: {seg_size}")
            seg_size = 0x4000000
        # Read segment bytes
        segment_data = ida_bytes.get_bytes(seg_start, seg_size)
        if not segment_data:
            print(f"[-] Failed to read segment data from {hex(seg_start)} to {hex(seg_end)}")
            return False
        
        # Write to file
        with open(filename, 'wb') as f:
            f.write(segment_data)
        
        print(f"[+] Successfully dumped segment to: {filename}")
        print(f"[+] Segment range: {hex(seg_start)} - {hex(seg_end)}")
        print(f"[+] Dumped size: {len(segment_data)} bytes ({hex(len(segment_data))})")
        return True
        
    except Exception as e:
        print(f"[-] Error during dump: {str(e)}")
        return False

def find_segment_by_address(target_addr):
    """
    Find segment containing the specified address
    """
    # Convert input to integer
    try:
        if isinstance(target_addr, str):
            if target_addr.startswith('0x'):
                addr_val = int(target_addr, 16)
            else:
                addr_val = int(target_addr)
        else:
            addr_val = target_addr
    except ValueError:
        print(f"[-] Invalid address format: {target_addr}")
        return None
    
    # Iterate through all segments
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg:
            seg_start = seg.start_ea
            seg_end = seg.end_ea
            
            if seg_start <= addr_val < seg_end:
                return seg
    
    print(f"[-] No segment found containing address: {hex(addr_val)}")
    return None

def dump_seg(seg_name, seg_start, seg_end, seg_class):
    global dumps_files

    filename = f"./dumps/segment_{seg_name}_{seg_class}_{hex(seg_start)}_{hex(seg_end)}_{hex(seg_end - seg_start)}.bin"

    if filename in dumps_files:
        return
    
    print(f"[+] Found segment: {seg_name}")
    print(f"[+] Segment class: {seg_class}")
    print(f"[+] Segment range: {hex(seg_start)} - {hex(seg_end)}")
    print(f"[+] Segment size: {hex(seg_end - seg_start)} bytes")
    
    # Dump segment to file
    dump_segment_to_file(seg_start, seg_end, filename)

    dumps_files.append(filename)

def dump_single_seg_addr(input_addr, range=0x10000):
    """
    Main function - get address from user and dump corresponding segment
    """
    dumped_range = []

    mem_list = os.listdir("./dumps")

    for i in mem_list:
        pattern = r'0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)\.bin$'
        match = re.search(pattern, i)
        if match:
            mem_base = int(match.group(1), 16)
            mem_end = int(match.group(2), 16)
            dumped_range.append((mem_base, mem_end))

    # Get target address from user
    if not input_addr:
        print("[-] No address provided")
        return
    
    if type(input_addr) == str:
        target_addr = int(input_addr[2:], 16) 
    else:
        target_addr = input_addr

    # Find segment containing the address
    seg = find_segment_by_address(target_addr)
    if not seg:
        print(f"[+] {target_addr} do not contain the addr")
        return
    
    dump_base = target_addr & (~(range - 1))
    
    # Get segment information
    seg_name = ida_segment.get_segm_name(seg)
    seg_start = seg.start_ea
    seg_end = seg.end_ea
    seg_class = ida_segment.get_segm_class(seg)
    
    print(f"[+] Found segment: {seg_name}")
    print(f"[+] Segment class: {seg_class}")
    print(f"[+] Segment range: {hex(seg_start)} - {hex(seg_end)}")
    print(f"[+] Segment size: {hex(seg_end - seg_start)} bytes")
    
    dump_end = dump_base + range
    if dump_end > seg_end:
        dump_end = seg_end
    if dump_base < seg_start:
        dump_base = seg_start
    
    for i in dumped_range:
        exist_start, exist_end = i
        if dump_base > exist_start and dump_base < exist_end:
            dump_base = exist_end
        if dump_end > exist_start and dump_end < exist_end:
            dump_end = exist_start
    
    if dump_base >= dump_end:
        print(f"[+] Range {hex(dump_base)} - {hex(dump_end)} already dumped")
        return
    
    dumped_range.append((dump_base, dump_end))
    # Generate output filename
    filename = f"./dumps/segment_{seg_name}_{hex(dump_base)}_{hex(dump_end)}_{hex(dump_end - dump_base)}.bin"
    
    # Dump segment to file
    dump_segment_to_file(dump_base, dump_end, filename)

if __name__ == "__main__":

    print("[+] DUMPING mem")
    dump_single_seg_addr(0x74dd244948, 0x100000)

    print("[+] Finish!")
