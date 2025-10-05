import sys
from log_parser import parse_log
from analyzer import analyze_events
from report import print_report

# --- GUI imports ---
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import tkinter.ttk as ttk
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
import csv

# Store last analysis and file path for visualization
last_analysis = {'analysis': None, 'file_path': None}


def run_gui():
    def set_status(msg):
        status_var.set(msg)
        status_label.update_idletasks()

    def select_file():
        file_path = filedialog.askopenfilename(
            title="Select log file",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")],
        )
        if file_path:
            set_status(f"Analyzing: {file_path.split('/')[-1]} ...")
            try:
                events = parse_log(file_path)
                analysis = analyze_events(events)
                report = get_report_str(analysis)
                text_area.config(state="normal")
                text_area.delete(1.0, tk.END)
                text_area.insert(tk.END, f"\n🚀 Analysis Report for: {file_path.split('/')[-1]} 🚀\n\n")
                text_area.insert(tk.END, report)
                text_area.config(state="disabled")
                set_status("Analysis complete! 🎉")
                last_analysis['analysis'] = analysis
                last_analysis['file_path'] = file_path
                update_tables(analysis)  # Update tables with new analysis
            except Exception as e:
                messagebox.showerror("Error", f"Failed to analyze log: {e}")
                set_status("Error during analysis.")
        else:
            set_status("Ready. Select a log file to analyze.")

    def clear_report():
        text_area.config(state="normal")
        text_area.delete(1.0, tk.END)
        text_area.config(state="disabled")
        set_status("Cleared. Ready for a new analysis!")
        last_analysis['analysis'] = None
        last_analysis['file_path'] = None
        # Clear tables
        for tbl in (failed_table, success_table, suspicious_table):
            for row in tbl.get_children():
                tbl.delete(row)

    def get_report_str(analysis):
        lines = []
        lines.append("=== Authentication Log Analysis Report ===\n")
        lines.append(f"Total failed login IPs: {len(analysis['failed'])}")
        lines.append(f"Total successful login IPs: {len(analysis['successful'])}")
        lines.append("\nSuspicious IPs (possible brute-force):")
        for ip in analysis["suspicious_ips"]:
            lines.append(f"  {ip} ({len(analysis['failed'][ip])} failed attempts)")
        lines.append("\n--- End of Report ---\n")
        return "\n".join(lines)

    def update_tables(analysis):
        # Clear tables
        for tbl in (failed_table, success_table, suspicious_table):
            for row in tbl.get_children():
                tbl.delete(row)
        # Fill failed logins
        failed_counts = sorted(analysis['failed'].items(), key=lambda x: len(x[1]), reverse=True)
        for ip, events in failed_counts:
            failed_table.insert('', 'end', values=(ip, len(events)))
        # Fill successful logins
        success_counts = sorted(analysis['successful'].items(), key=lambda x: len(x[1]), reverse=True)
        for ip, events in success_counts:
            success_table.insert('', 'end', values=(ip, len(events)))
        # Fill suspicious IPs
        for ip in analysis['suspicious_ips']:
            suspicious_table.insert('', 'end', values=(ip, len(analysis['failed'][ip])))

    def export_csv():
        analysis = last_analysis['analysis']
        if not analysis:
            messagebox.showinfo("Info", "Please analyze a log file first.")
            return
        export_type = export_var.get()
        rows = []
        header = []
        fname = ''
        if export_type == 'Failed':
            rows = [(ip, len(events)) for ip, events in analysis['failed'].items()]
            header = ['IP', 'Failed Attempts']
            fname = 'failed_logins.csv'
        elif export_type == 'Successful':
            rows = [(ip, len(events)) for ip, events in analysis['successful'].items()]
            header = ['IP', 'Successful Logins']
            fname = 'successful_logins.csv'
        elif export_type == 'Suspicious':
            rows = [(ip, len(analysis['failed'][ip])) for ip in analysis['suspicious_ips']]
            header = ['IP', 'Suspicious Failed Attempts']
            fname = 'suspicious_ips.csv'
        elif export_type == 'All':
            # Export all attempts (failed and successful) with timestamp, IP, and status
            file_path = last_analysis['file_path']
            if not file_path:
                messagebox.showinfo("Info", "No log file loaded.")
                return
            with open(file_path, 'r') as f:
                for line in f:
                    if "Failed password" in line or "Accepted password" in line:
                        try:
                            ts_str = line[:15]
                            ts = datetime.strptime(ts_str, "%b %d %H:%M:%S")
                            ts = ts.replace(year=datetime.now().year)
                            ip = None
                            if "from " in line:
                                ip_part = line.split("from ")[-1].split()[0]
                                ip = ip_part
                            status = 'Failed' if "Failed password" in line else 'Successful'
                            rows.append((ts.strftime("%Y-%m-%d %H:%M:%S"), ip, status))
                        except Exception:
                            continue
            header = ['Timestamp', 'IP', 'Status']
            fname = 'all_login_attempts.csv'
        if not rows:
            messagebox.showinfo("Info", f"No {export_type.lower()} data to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension='.csv', initialfile=fname, filetypes=[('CSV files', '*.csv')])
        if file_path:
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(header)
                writer.writerows(rows)
            messagebox.showinfo("Exported", f"Exported to {file_path}")

    def visualize_selected():
        analysis = last_analysis['analysis']
        file_path = last_analysis['file_path']
        if not analysis or not file_path:
            messagebox.showinfo("Info", "Please analyze a log file first.")
            return
        vis_type = vis_var.get()
        events = []
        if vis_type == 'All':
            # Show all failed and successful attempts
            with open(file_path, 'r') as f:
                for line in f:
                    if "Failed password" in line or "Accepted password" in line:
                        try:
                            ts_str = line[:15]
                            ts = datetime.strptime(ts_str, "%b %d %H:%M:%S")
                            ts = ts.replace(year=datetime.now().year)
                            # Extract IP
                            ip = None
                            if "from " in line:
                                ip_part = line.split("from ")[-1].split()[0]
                                ip = ip_part
                            label = 'Failed' if "Failed password" in line else 'Successful'
                            color = 'red' if label == 'Failed' else 'green'
                            events.append((ts, ip, label, color))
                        except Exception:
                            continue
            if not events:
                messagebox.showinfo("Info", "No login attempts found in log.")
                return
            # Plot all attempts, color-coded
            events.sort()
            times = [e[0] for e in events]
            ips = [e[1] for e in events]
            labels = [e[2] for e in events]
            colors = [e[3] for e in events]
            ip_set = sorted(list(set(ips)))
            ip_to_y = {ip: i for i, ip in enumerate(ip_set)}
            y_vals = [ip_to_y[ip] for ip in ips]
            plt.figure(figsize=(10, 5))
            for label in set(labels):
                idxs = [i for i, l in enumerate(labels) if l == label]
                plt.scatter([times[i] for i in idxs], [y_vals[i] for i in idxs],
                            c=[colors[i] for i in idxs], label=label, alpha=0.7)
            plt.yticks(range(len(ip_set)), ip_set)
            plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            plt.xlabel('Timestamp')
            plt.ylabel('IP Address')
            plt.title('All Login Attempts (Timestamp vs IP)')
            plt.tight_layout()
            plt.legend()
            plt.show()
            return
        # ...existing code for Suspicious, Failed, Successful...
        if vis_type == 'Suspicious':
            ip_list = analysis['suspicious_ips']
            label = 'Suspicious Failed Attempt'
            color = 'red'
            filter_str = 'Failed password'
        elif vis_type == 'Failed':
            ip_list = analysis['failed'].keys()
            label = 'Failed Attempt'
            color = 'orange'
            filter_str = 'Failed password'
        else:
            ip_list = analysis['successful'].keys()
            label = 'Successful Login'
            color = 'green'
            filter_str = 'Accepted password'
        with open(file_path, 'r') as f:
            for line in f:
                for ip in ip_list:
                    if ip in line and filter_str in line:
                        try:
                            ts_str = line[:15]
                            ts = datetime.strptime(ts_str, "%b %d %H:%M:%S")
                            ts = ts.replace(year=datetime.now().year)
                            events.append((ts, ip))
                        except Exception:
                            continue
        if not events:
            messagebox.showinfo("Info", f"No {vis_type.lower()} events found in log.")
            return
        events.sort()
        times = [e[0] for e in events]
        ips = [e[1] for e in events]
        ip_set = sorted(list(set(ips)))
        ip_to_y = {ip: i for i, ip in enumerate(ip_set)}
        y_vals = [ip_to_y[ip] for ip in ips]
        plt.figure(figsize=(10, 5))
        plt.scatter(times, y_vals, c=color, label=label)
        plt.yticks(range(len(ip_set)), ip_set)
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.xlabel('Timestamp')
        plt.ylabel('IP Address')
        plt.title(f'{label}s (Timestamp vs IP)')
        plt.tight_layout()
        plt.legend()
        plt.show()

    root = tk.Tk()
    root.title("Authentication Log Analyzer")
    root.geometry("900x650")

    # Welcome banner
    welcome = tk.Label(root, text="🔒 Welcome to the Authentication Log Analyzer! 🔍", font=("Arial", 16, "bold"), fg="#2a7ae2")
    welcome.pack(pady=(10, 0))

    # Button frame (top row)
    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)
    btn = tk.Button(btn_frame, text="Select Log File", command=select_file)
    btn.pack(side=tk.LEFT, padx=5)
    clear_btn = tk.Button(btn_frame, text="Clear", command=clear_report)
    clear_btn.pack(side=tk.LEFT, padx=5)

    # Visualization and export controls (second row)
    btn_frame2 = tk.Frame(root)
    btn_frame2.pack(pady=0)
    vis_var = tk.StringVar(value='Suspicious')
    vis_menu = ttk.Combobox(btn_frame2, textvariable=vis_var, values=['Suspicious', 'Failed', 'Successful', 'All'], state='readonly', width=12)
    vis_menu.pack(side=tk.LEFT, padx=5)
    vis_btn = tk.Button(btn_frame2, text="Visualize", command=visualize_selected)
    vis_btn.pack(side=tk.LEFT, padx=5)
    export_var = tk.StringVar(value='Failed')
    export_menu = ttk.Combobox(btn_frame2, textvariable=export_var, values=['Failed', 'Successful', 'Suspicious', 'All'], state='readonly', width=12)
    export_menu.pack(side=tk.LEFT, padx=5)
    export_btn = tk.Button(btn_frame2, text="Export CSV", command=export_csv)
    export_btn.pack(side=tk.LEFT, padx=5)

    # Tabs for report and tables
    tabs = ttk.Notebook(root)
    tabs.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    # Report tab
    report_frame = tk.Frame(tabs)
    tabs.add(report_frame, text='Report')
    text_area = scrolledtext.ScrolledText(
        report_frame, wrap=tk.WORD, width=80, height=25, state="disabled"
    )
    text_area.pack(fill=tk.BOTH, expand=True)
    # Failed logins tab
    failed_frame = tk.Frame(tabs)
    tabs.add(failed_frame, text='Failed Logins')
    failed_table = ttk.Treeview(failed_frame, columns=('IP', 'Count'), show='headings', height=20)
    failed_table.heading('IP', text='IP Address')
    failed_table.heading('Count', text='Failed Attempts')
    failed_table.pack(fill=tk.BOTH, expand=True)
    # Successful logins tab
    success_frame = tk.Frame(tabs)
    tabs.add(success_frame, text='Successful Logins')
    success_table = ttk.Treeview(success_frame, columns=('IP', 'Count'), show='headings', height=20)
    success_table.heading('IP', text='IP Address')
    success_table.heading('Count', text='Successful Logins')
    success_table.pack(fill=tk.BOTH, expand=True)
    # Suspicious IPs tab
    suspicious_frame = tk.Frame(tabs)
    tabs.add(suspicious_frame, text='Suspicious IPs')
    suspicious_table = ttk.Treeview(suspicious_frame, columns=('IP', 'Count'), show='headings', height=20)
    suspicious_table.heading('IP', text='IP Address')
    suspicious_table.heading('Count', text='Failed Attempts')
    suspicious_table.pack(fill=tk.BOTH, expand=True)

    # Status bar
    status_var = tk.StringVar()
    status_var.set("Ready. Select a log file to analyze.")
    status_label = tk.Label(root, textvariable=status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W, fg="#444")
    status_label.pack(fill=tk.X, side=tk.BOTTOM, ipady=2)

    # Update tables after analysis
    def after_analysis(analysis):
        update_tables(analysis)

    # Patch select_file to update tables
    orig_select_file = select_file
    def patched_select_file():
        orig_select_file()
        analysis = last_analysis['analysis']
        if analysis:
            after_analysis(analysis)
    btn.config(command=patched_select_file)

    root.mainloop()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        run_gui()
        return
    if len(sys.argv) < 2:
        print("Usage: python main.py <logfile> OR python main.py --gui")
        sys.exit(1)
    logfile = sys.argv[1]
    events = parse_log(logfile)
    analysis = analyze_events(events)
    print_report(analysis)


if __name__ == "__main__":
    main()
