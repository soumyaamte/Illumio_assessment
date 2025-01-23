import csv
import sys

# Mapping protocol numbers to protocol names
PROTOCOL_MAP = {
    "6": "tcp",    # Transmission Control Protocol
    "17": "udp",   # User Datagram Protocol
    "1": "icmp",   # Internet Control Message Protocol
    "47": "gre",   # Generic Routing Encapsulation
}

def load_lookup_table(file_path):
    """Load the lookup table from a CSV file."""
    try:
        with open(file_path, 'r') as file:
            reader = csv.DictReader(file)
            lookup_table = {}
            for row in reader:
                dstport = row['dstport'].strip()
                protocol = row['protocol'].strip().lower()
                tag = row['tag'].strip()
                lookup_table[(dstport, protocol)] = tag
            return lookup_table
    except Exception as e:
        print(f"Error loading lookup table: {e}")
        sys.exit(1)

def parse_flow_logs(file_path):
    """Parse the flow log file and extract relevant fields."""
    flow_logs = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                parts = line.split()
                if len(parts) < 14:  # Ensure line has enough fields
                    continue
                flow_logs.append({
                    'dstport': parts[6],
                    'protocol': parts[7],
                })
        return flow_logs
    except Exception as e:
        print(f"Error reading flow logs: {e}")
        sys.exit(1)

def process_logs(flow_logs, lookup_table):
    """Process the flow logs to count tags and port/protocol combinations."""
    tag_counts = {}
    port_protocol_counts = {}

    for entry in flow_logs:
        dstport = entry['dstport']
        protocol_num = entry['protocol']
        protocol_name = PROTOCOL_MAP.get(protocol_num, "unknown")

        # Determine the tag
        tag = lookup_table.get((dstport, protocol_name), "Untagged")
        tag_counts[tag] = tag_counts.get(tag, 0) + 1

        # Count port/protocol combinations
        key = f"{dstport},{protocol_name}"
        port_protocol_counts[key] = port_protocol_counts.get(key, 0) + 1

    return tag_counts, port_protocol_counts

def write_output(output_path, tag_counts, port_protocol_counts):
    """Write the results to the output file."""
    try:
        with open(output_path, 'w') as output_file:
            # Write tag counts
            output_file.write("Tag Counts:\n\n")
            output_file.write("Tag,Count\n")
            for tag, count in sorted(tag_counts.items()):
                output_file.write(f"{tag},{count}\n")

            # Write port/protocol combination counts
            output_file.write("\nPort/Protocol Combination Counts:\n\n")
            output_file.write("Port,Protocol,Count\n")
            for key, count in sorted(port_protocol_counts.items()):
                port, protocol = key.split(',')
                output_file.write(f"{port},{protocol},{count}\n")

    except Exception as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 flow_log_parser.py <flow_log_file> <lookup_table_file> <output_file>")
        sys.exit(1)

    flow_log_file = sys.argv[1]
    lookup_table_file = sys.argv[2]
    output_file = sys.argv[3]

    lookup_table = load_lookup_table(lookup_table_file)
    flow_logs = parse_flow_logs(flow_log_file)
    tag_counts, port_protocol_counts = process_logs(flow_logs, lookup_table)
    write_output(output_file, tag_counts, port_protocol_counts)

if __name__ == "__main__":
    main()
