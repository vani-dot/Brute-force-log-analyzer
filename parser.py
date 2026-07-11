def parse_line(line):
    words = line.split()
    from_index = words.index("from")
    ip = words[from_index + 1]
    time = words[2]
    if "Failed" in line:    
        result = "failed"
    else:
        result = "success"
    return time, ip, result 

def time_to_seconds(time_str):
    time_parts = time_str.split(":")
    hours = int(time_parts[0])
    minutes = int(time_parts[1])
    seconds = int(time_parts[2])
    total = hours * 3600 + minutes * 60 + seconds
    return total