from parser import parse_line, time_to_seconds

def analyze_log(filename):
    f = open("auth_sample.log")
    failed_attempts = {}
    for line in f:
        time, ip, result = parse_line(line)
        if result == "failed":
            if ip not in failed_attempts:
                failed_attempts[ip] = []
            failed_attempts[ip].append(time)
    found = False
    for ip, times in failed_attempts.items():
        seconds_list = []
        for t in times:
            seconds_list.append(time_to_seconds(t))
        if len(seconds_list) >= 5:
            for i in range(len(seconds_list) - 4):
                if seconds_list[i + 4] - seconds_list[i] <= 120:
                    print(f"ALERT: {ip} had 5+ failed logins between {times[i]} and {times[i + 4]}")
                    found = True
                    break
    if found == False:
        print("No threats detected.")

    