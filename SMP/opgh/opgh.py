import json


__author__ = "Jair Lijkwan 500851983"

SUSPICIOUS_ACTIVITY_DB = {
    "office_hours_start": "07:00",
    "office_hours_end": "18:00",
    "payloads": ["pen-test", "66"],
    "host_pairs": [("145.18.11.151", "115.105.116.104"), ("145.18.11.151", "192.168.4.1")]
}


def load_jsonfile(filepath):
    with open(filepath, "r") as f:
        return json.load(f)


class SessionMessage():
    def __init__(self, nr, timestamp, payload):
        self.nr = nr
        self.timestamp = timestamp
        self.payload = payload


class NetworkSession():
    def __init__(self, src_ip, src_port, dst_ip, dst_port, messages):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.messages = messages

    def detect_suspicious_activity(self, suspicous_activity_db):
        """Checks payloads, banned host communication and communication outside office hours

        suspicious_activity_db contains the definitions of suspicious activity*

        *see SUSPICIOUS_ACTIVITY_DB top of file

        Returns a list of messages indicating suspicious activity"""
        raise NotImplementedError


def normalize_source_and_destination(log_entry):
    """Normalizes log_entry with
    destination to dest_ip, dest_port
    source to src_ip, src_port
    
    Takes a log_entry and returns the normalized log_entry
    log_entry is a dict in the form that can be found in networkdata.json
    """

    timestamp = log_entry["timestamp"]
    msg_no = log_entry["msg_no"]
    payload = log_entry["payload"]
    dictionary = {"timestamp": timestamp, "msg_no": msg_no, "payload": payload, }
    if "source" in log_entry:
        log_entry["src_ip"] = log_entry.pop("source")
        src_ip = log_entry["src_ip"]
        src_ip, src_port = src_ip.split(":")
        dictionary["src_ip"] = src_ip
        dictionary["src_port"] = int(src_port)
    else:
        dictionary["src_ip"] = log_entry["src_ip"]
        dictionary["src_port"] = int(log_entry["src_port"])
    if "destination" in log_entry:
        log_entry["dest_ip"] = log_entry.pop("destination")
        dest_ip = log_entry["dest_ip"]
        dest_ip, dest_port = dest_ip.split(":")
        dictionary["dest_ip"] = dest_ip
        dictionary["dest_port"] = int(dest_port)
    else:
        dictionary["dest_ip"] = log_entry["dest_ip"]
        dictionary["dest_port"] = int(log_entry["dest_port"])
    return dictionary
    
    
def normalize_whitespace(log_entry):
    """Normalizes log_entry by removing leading and trailing whitespace
    in all string values except the payload
    
    Takes a log_entry and returns the normalized log_entry
    log_entry is a dict in the form that can be found in networkdata.json
    """
    keys_to_modify = ["src_ip", "dest_ip", "source", "destination", "timestamp", ]
    for key in keys_to_modify:
        if key in log_entry:
            log_entry[key] = log_entry[key].strip()
    return log_entry
    
def normalize_ip(log_entry):
    """Normalizes log_entry by converting all semicolons in ip addresses to dots.
    
    Takes a log_entry and returns the normalized log_entry
    log_entry is a dict in the form that can be found in networkdata.json
    """
    keys_to_modify = ["src_ip", "dest_ip", "source", "destination", ]
    for key in keys_to_modify:
        if key in log_entry:
            log_entry[key] = log_entry[key].replace(",", ".")
    return log_entry


def network_session_messages(src_ip, src_port, dest_ip, dest_port, log_entries):
    """Gathers all messages belonging to a specific session
    
    src_ip, src_port, dest_ip and dest_port designate the session
    log_entries is the list of normalized networkdata

    returns a list containing SessionMessage objects
    """
    messages = []
    for entry in log_entries:
        if src_ip != entry["src_ip"] and dest_ip != entry["src_ip"]:
            continue
        if src_port != entry["src_port"] and dest_port != entry["src_port"]:
            continue
        if dest_ip != entry["dest_ip"] and src_ip != entry["dest_ip"]:
            continue
        if dest_port != entry["dest_port"] and src_port != entry["dest_port"]:
            continue
        message = SessionMessage(entry["msg_no"], entry["timestamp"], entry["payload"])
        messages.append(message)
    return messages

def contains_entry(src_ip, src_port, dest_ip, dest_port, sessions):
    for session in sessions:
        has_src_ip = src_ip == session.src_ip or src_ip == session.dst_ip
        has_src_port = src_port == session.src_port or src_port == session.dst_port
        has_dest_ip = dest_ip == session.dst_ip or dest_ip == session.src_ip
        has_dest_port = dest_port == session.dst_port or dest_port == session.src_port
        if has_src_ip and has_src_port and has_dest_ip and has_dest_port:
            return True
    return False


def network_sessions(log_entries):
    """Gathers all network session that can be identified in the networkdata
    
    log_entries is the list of normalized networkdata
    
    returns a list containing NetworkSession objects"""
    sess = []
    for entry in log_entries:
        if contains_entry(entry["src_ip"], entry["src_port"], entry["dest_ip"], entry["dest_port"], sess):
            continue
        msg = network_session_messages(entry["src_ip"], entry["src_port"], entry["dest_ip"], entry["dest_port"], log_entries)
        sess.append(NetworkSession(entry["src_ip"], entry["src_port"], entry["dest_ip"], entry["dest_port"], msg))
    return sess

def generate_report(sessions, suspicious_activity_db):
    """Generate a report based on all network sessions
    
    sessions is a list of of NetworkSession objects
    suspicious_activity_db contains the definitions of suspicious activity*

    *see SUSPICIOUS_ACTIVITY_DB top of file
    
    return a string containing the report"""
    raise NotImplementedError


def main():
    def normalize(log):
        log = normalize_source_and_destination(log)
        log = normalize_whitespace(log)
        return normalize_ip(log)
    
    logs = load_jsonfile("network_session_data.json")
    logs = [normalize(log) for log in logs]
    
    sessions = network_sessions(logs)
    report = generate_report(sessions, SUSPICIOUS_ACTIVITY_DB)
    print(report)


if __name__ == "__main__":
    main()
