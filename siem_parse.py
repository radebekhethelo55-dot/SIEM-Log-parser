import re
import csv
import argparse
from collections import defaultdict

def parse_logs(file_path, threshold=3, output_csv=None):
    """
    Parses an SSH authentication log file to count failed login attempts 
    per IP address and flag potential brute-force attacks.
    """
    # Regex pattern to capture the IP address from SSH failed password lines
    failed_login_pattern = re.compile(r"Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    
    failed_attempts = defaultdict(int)

    try:
        with open(file_path, "r") as log_file:
            for line in log_file:
                match = failed_login_pattern.search(line)
                if match:
                    ip_address = match.group(1)
                    failed_attempts[ip_address] += 1

        print("\n" + "=" * 50)
        print("          SIEM LOG PARSER REPORT")
        print("=" * 50)
        print(f"{'IP Address':<20} | {'Failed Attempts':<15} | {'Status'}")
        print("-" * 50)

        results = []
        suspicious_found = False

        for ip, count in failed_attempts.items():
            if count >= threshold:
                status = "ALERT: Potential Brute-Force!"
                display_status = "🚨 ALERT: Potential Brute-Force!"
                suspicious_found = True
            else:
                status = "Normal Activity"
                display_status = "ℹ️  Normal Activity"
            
            print(f"{ip:<20} | {count:<15} | {display_status}")
            results.append({"IP Address": ip, "Failed Attempts": count, "Status": status})

        if not suspicious_found:
            print("\nNo suspicious activity detected exceeding the threshold.")

        print("=" * 50 + "\n")

        # Export to CSV if an output file path is provided
        if output_csv:
            with open(output_csv, mode="w", newline="") as csv_file:
                fieldnames = ["IP Address", "Failed Attempts", "Status"]
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
            print(f"[+] Report saved successfully to '{output_csv}'\n")

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple SIEM Log Parser for SSH Authentication Logs.")
    parser.add_argument("-f", "--file", required=True, help="Path to the log file to parse")
    parser.add_argument("-t", "--threshold", type=int, default=3, help="Threshold for failed logins to trigger an alert (default: 3)")
    parser.add_argument("-o", "--output", type=str, help="Optional CSV output file name (e.g., report.csv)")
    
    args = parser.parse_args()
    parse_logs(args.file, args.threshold, args.output)