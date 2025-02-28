def parse_log_line(log_line):
    parts = log_line.split(" - ")
    if len(parts) < 3:
        return None
    timestamp = parts[0]
    level = parts[1]
    message = " - ".join(parts[2:])
    return {"timestamp": timestamp, "level": level, "message": message}

def extract_user_activity(log_entry):
    if "User:" in log_entry:
        user_info = log_entry.split("User:")[1].strip()
        return user_info.split(" - ")[0]
    return None

def is_malicious_activity(log_entry):
    return "RATE LIMIT" in log_entry or "ERROR" in log_entry

def parse_log_file(file_path):
    parsed_entries = []
    with open(file_path, 'r') as file:
        for line in file:
            parsed_line = parse_log_line(line.strip())
            if parsed_line:
                parsed_entries.append(parsed_line)
    return parsed_entries