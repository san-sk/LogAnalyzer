def print_report(analysis):
    def ascii_bar(count, max_count, width=40):
        bar_len = int((count / max_count) * width) if max_count else 0
        return '█' * bar_len + f' ({count})'

    print("\n=== Authentication Log Analysis Report ===\n")
    total_failed = sum(len(v) for v in analysis['failed'].values())
    total_success = sum(len(v) for v in analysis['successful'].values())
    print(f"Total failed login attempts: {total_failed}")
    print(f"Total successful login attempts: {total_success}")
    print("\n[Login Attempts Overview]")
    max_total = max(total_failed, total_success, 1)
    print(f"Failed   : {ascii_bar(total_failed, max_total)}")
    print(f"Success  : {ascii_bar(total_success, max_total)}\n")

    # Top 5 failed IPs
    print("Top 5 IPs with most failed login attempts:")
    failed_counts = sorted(analysis['failed'].items(), key=lambda x: len(x[1]), reverse=True)
    max_failed = len(failed_counts[0][1]) if failed_counts else 1
    for ip, events in failed_counts[:5]:
        print(f"  {ip:15} {ascii_bar(len(events), max_failed)}")
    if not failed_counts:
        print("  (none)")
    print()

    # Top 5 successful IPs
    print("Top 5 IPs with most successful logins:")
    success_counts = sorted(analysis['successful'].items(), key=lambda x: len(x[1]), reverse=True)
    max_success = len(success_counts[0][1]) if success_counts else 1
    for ip, events in success_counts[:5]:
        print(f"  {ip:15} {ascii_bar(len(events), max_success)}")
    if not success_counts:
        print("  (none)")
    print()

    print("Suspicious IPs (possible brute-force):")
    for ip in analysis['suspicious_ips']:
        print(f"  {ip} ({len(analysis['failed'][ip])} failed attempts)")
    if not analysis['suspicious_ips']:
        print("  (none)")
    print("\n--- End of Report ---\n")
