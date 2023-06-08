import json

__author__ = "Name and studentnumber"

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
    raise NotImplementedError


def normalize_whitespace(log_entry):
    """Normalizes log_entry by removing leading and trailing whitespace
    in all string values except the payload
    
    Takes a log_entry and returns the normalized log_entry
    log_entry is a dict in the form that can be found in networkdata.json
    """
    raise NotImplementedError


def normalize_ip(log_entry):
    """Normalizes log_entry by converting all semicolons in ip addresses to dots.
    
    Takes a log_entry and returns the normalized log_entry
    log_entry is a dict in the form that can be found in networkdata.json
    """
    raise NotImplementedError


def network_session_messages(src_ip, src_port, dest_ip, dest_port, log_entries):
    """Gathers all messages belonging to a specific session
    
    src_ip, src_port, dest_ip and dest_port designate the session
    log_entries is the list of normalized networkdata

    returns a list containing SessionMessage objects
    """
    raise NotImplementedError


def network_sessions(log_entries):
    """Gathers all network session that can be identified in the networkdata
    
    log_entries is the list of normalized networkdata
    
    returns a list containing NetworkSession objects"""
    raise NotImplementedError


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
