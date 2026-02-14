import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import os
import threading
import sys
import subprocess

# importing from EmailScore
from EmailScore import *
from EmailVerify.main import Email

from LangAnalysis.email_extract import *


class EmailScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Email Scanner")
        self.geometry("900x500")

        self.folder_path = tk.StringVar()

        self.email_cache = {}

        self.total_emails = 0
        self.processed_emails = 0

        # Variable for offline checkbox 
        self.offline_mode = tk.BooleanVar(value=False)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # risk counters
        self.low_count = 0
        self.medium_count = 0
        self.high_count = 0



        self.create_widgets()

    def create_widgets(self):
        # Top controls
        top_frame = tk.Frame(self)
        top_frame.pack(fill="x", padx=10, pady=5)

        tk.Button(
            top_frame,
            text="Select Folder",
            command=self.select_folder
        ).pack(side="left")

        tk.Button(
            top_frame,
            text="Scan Single Email",
            command=self.scan_single_email
        ).pack(side="left", padx=5)

        tk.Label(
            top_frame,
            textvariable=self.folder_path,
            wraplength=600,
            anchor="w"
        ).pack(side="left", padx=10)

        tk.Button(
            top_frame,
            text="Scan Emails",
            command=self.start_scan,
            fg="white",
            bg="green"
        ).pack(side="right")

        # Checkbox
        checkbox_frame = tk.Frame(self)
        checkbox_frame.pack(fill="x", padx=10)

        tk.Checkbutton(
            checkbox_frame,
            text="Offline mode (no internet)",
            variable=self.offline_mode,
            command=self.toggle_offline_mode
        ).pack(side="left")

        # Button to clear all logs
        tk.Button(
            checkbox_frame,
            text="Clear All Logs",
            command=self.clear_logs,
            fg="white",
            bg="red"
        ).pack(side="left", padx=10)

        # Disabled until batch scan is complete
        self.chart_button = tk.Button(
            checkbox_frame,
            text="Show Risk Chart",
            command=self.show_pie_chart,
            state="disabled",
            fg="white",
            bg="#007bff"
        )
        self.chart_button.pack(side="left", padx=10)

        # Table
        columns = ("file", "sender", "subject", "risk", "level")

        self.tree = ttk.Treeview(
            self,
            columns=columns,
            show="headings",
            height=18
        )

        self.tree.bind("<Double-1>", self.open_email_details)

        self.tree.heading("file", text="File")
        self.tree.heading("sender", text="Sender")
        self.tree.heading("subject", text="Subject")
        self.tree.heading("risk", text="Risk %")
        self.tree.heading("level", text="Risk Level")

        self.tree.column("file", width=180)
        self.tree.column("sender", width=200)
        self.tree.column("subject", width=260)
        self.tree.column("risk", width=80, anchor="center")
        self.tree.column("level", width=120, anchor="center")

        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        # Chart Display Frame
        self.chart_frame = tk.LabelFrame(self, text="Risk Distribution")
        self.chart_frame.pack(fill="both", expand=False, padx=10, pady=(0,10))

        self.chart_canvas = None  # will hold matplotlib canvas


        # Color tags
        self.tree.tag_configure("low", background="#d4edda")
        self.tree.tag_configure("medium", background="#fff3cd")
        self.tree.tag_configure("high", background="#f8d7da")

        # Loading overlay
        self.loading_frame = tk.Frame(self, bg="#000000")

        self.loading_label = tk.Label(
            self.loading_frame,
            text="Scanning emails...",
            fg="white",
            bg="#000000",
            font=("Arial", 14)
        )

        self.progress = ttk.Progressbar(
            self.loading_frame,
            mode="determinate",
            length=300
        )

        self.progress_text = tk.Label(
            self.loading_frame,
            text="0 / 0",
            fg="white",
            bg="#000000",
            font=("Arial", 10)
        )


        self.loading_label.pack(pady=10)
        self.progress.pack(pady=5)
        self.progress_text.pack()

    #---------------------------------------- Scanning folder --------------------------------------------#

    def ensure_eml(self, file_path):
        """
        If the file is not .eml, convert it to .eml using EmailExtract and mark it for deletion later.
        Returns the path to the .eml file.
        """
        if file_path.lower().endswith(".eml"):
            return file_path
        else:
            eml_file = Email.convert_to_eml(file_path)
            if not hasattr(self, "temp_eml_files"):
                self.temp_eml_files = []
            self.temp_eml_files.append(eml_file)
            return eml_file


    def select_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.folder_path.set(path)

    def start_scan(self):
        # enforces offline setting 
        self.apply_offline_setting()
        
        if not self.folder_path.get():
            messagebox.showerror("Error", "Please select a folder first")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        folder = self.folder_path.get()
        all_files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]

        if not all_files:
            messagebox.showinfo("Info", "No .eml files found")
            return

        self.show_loading(len(all_files))

        threading.Thread(
            target=self.scan_folder_worker,
            args=(all_files,),
            daemon=True
        ).start()


    def toggle_offline_mode(self):
        if self.offline_mode.get():
            enable_offline_mode()
            messagebox.showinfo(
                "Offline Mode Enabled",
                "Internet access has been disabled.\n"
                "URL reputation and online checks will not work."
            )
        else:
            disable_offline_mode()
            messagebox.showinfo(
                "Offline Mode Disabled",
                "Internet access has been restored."
            )

    def on_close(self):
        disable_offline_mode()
        self.destroy()


    def apply_offline_setting(self):
        if self.offline_mode.get():
            enable_offline_mode()
        else:
            disable_offline_mode()


    def scan_folder_worker(self, all_files):
        folder = self.folder_path.get()

        for filename in all_files:

            # Ensures that the files are all .eml
            file_path = os.path.join(folder, filename)
            eml_file_path = self.ensure_eml(file_path)

            try:
                email = Email(eml_file_path)

                (
                    doc_score,
                    url_score,
                    email_score,
                    lang_score,
                    attachment_flag,
                    url_flag,
                    final_score,
                    details
                ) = scoringSystem(email)


                level, tag = self.risk_level(final_score)

                self.after(
                    0,
                    self.add_result_row,
                    filename,
                    email,
                    final_score,
                    level,
                    tag,
                    details
                )

            except Exception as e:
                print(f"Error scanning {filename}: {e}")

            self.processed_emails += 1
            self.after(0, self.update_progress)

        self.after(0, self.hide_loading)

        # Enable chart button after batch scan
        self.after(0, lambda: self.chart_button.config(state="normal"))


        # Clean up temp .eml files
        if hasattr(self, "temp_eml_files"):
            for temp_file in self.temp_eml_files:
                try:
                    os.remove(temp_file)
                except Exception as e:
                    print(f"Failed to delete temp file {temp_file}: {e}")
            self.temp_eml_files.clear()

        


    def scan_folder_wrapper(self):
        try:
            self.scan_folder()
        finally:
            self.after(0, self.hide_loading)


    #---------------------------------------- Scanning a single email --------------------------------------------#


    def scan_single_email(self):

        self.apply_offline_setting()

        file_path = filedialog.askopenfilename(
            title="Select a .eml file",
            filetypes=[("Email Files", "*.eml")]
        )
        
        if not file_path:
            return

        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.show_loading(1)  # Only 1 email to scan

        # Start scanning in a thread to avoid freezing
        threading.Thread(
            target=self.scan_single_worker,
            args=(file_path,),
            daemon=True
        ).start()


    def scan_single_worker(self, file_path):

        
        # Track temporary .eml files
        temp_files = []

        try:

            eml_file = self.ensure_eml(file_path)
            if eml_file != file_path:
                temp_files.append(eml_file)

            email = Email(eml_file)

            (
                doc_score,
                url_score,
                email_score,
                lang_score,
                attachment_flag,
                url_flag,
                final_score,
                details
            ) = scoringSystem(email)

            level, tag = self.risk_level(final_score)

            self.after(
                0,
                self.add_result_row,
                os.path.basename(file_path),
                email,
                final_score,
                level,
                tag,
                details
            )

        except Exception as e:
            print(f"Error scanning {file_path}: {e}")

        self.processed_emails += 1
        self.after(0, self.update_progress)
        self.after(0, self.hide_loading)

        # Delete any temporary .eml files created
        for temp_file in temp_files:
            try:
                os.remove(temp_file)
            except Exception as e:
                print(f"Failed to delete temp file {temp_file}: {e}")



    def open_email_details(self, event):
        selected = self.tree.selection()
        if not selected:
            return

        data = self.email_cache.get(selected[0])
        if not data:
            return

        window = tk.Toplevel(self)
        window.title(f"Email Details - {data['filename']}")
        window.geometry("900x550")

        # ===== Header =====
        header = tk.Frame(window)
        header.pack(fill="x", padx=10, pady=5)

        info = [
            ("From:", data["sender"]),
            ("Subject:", data["subject"]),
            ("Risk:", f"{data['risk']} ({data['level']})")
        ]

        for i, (label, value) in enumerate(info):
            tk.Label(header, text=label, font=("Arial", 10, "bold")).grid(row=i, column=0, sticky="w")
            tk.Label(header, text=value, wraplength=700).grid(row=i, column=1, sticky="w")

        ttk.Separator(window, orient="horizontal").pack(fill="x", pady=5)

        # ===== Main Content =====
        main = tk.Frame(window)
        main.pack(fill="both", expand=True)

        # --- Email Body ---
        body_frame = tk.LabelFrame(main, text="Email Body")
        body_frame.pack(fill="both", expand=True, padx=10, pady=10)

        body_scroll = tk.Scrollbar(body_frame)
        body_scroll.pack(side="right", fill="y")

        body_text = tk.Text(
            body_frame,
            wrap="word",
            yscrollcommand=body_scroll.set
        )
        body_text.pack(fill="both", expand=True)
        body_scroll.config(command=body_text.yview)

        body_text.insert("1.0", data["body"])
        body_text.config(state="disabled")

        # ===== Open Corresponding Log File =====
        log_file_path = data.get("log_path")

        if log_file_path and os.path.exists(log_file_path):
            try:
                if sys.platform.startswith("win"):
                    os.startfile(log_file_path)
                elif sys.platform.startswith("darwin"):
                    subprocess.Popen(["open", log_file_path])
                else:
                    subprocess.Popen(["xdg-open", log_file_path])
            except Exception as e:
                print(f"Failed to open log file: {e}")
        else:
            print("Log file not found.")




    def show_loading(self, total):

        self.total_emails = total
        self.processed_emails = 0

        # Reset counters
        self.low_count = 0
        self.medium_count = 0
        self.high_count = 0

        # Disable chart button
        self.chart_button.config(state="disabled")

        self.progress["maximum"] = total
        self.progress["value"] = 0
        self.progress_text.config(text=f"0 / {total}")

        self.loading_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.update_idletasks()


    def hide_loading(self):
        disable_offline_mode()
        self.loading_frame.place_forget()

        # Enable chart button only if emails were scanned
        if self.total_emails > 0:
            self.chart_button.config(state="normal")


    def update_progress(self):
        self.progress["value"] = self.processed_emails
        self.progress_text.config(
            text=f"{self.processed_emails} / {self.total_emails}"
        )


    def add_result_row(self, filename, email, score, level, tag, details):
        
        # --- Write log file for this email ---
        log_path = self.write_log_file(
            filename=filename,
            final_score=f"{score:.2f}%",
            level=level,
            details=details
        )
        
        item_id = self.tree.insert(
            "",
            "end",
            values=(
                filename,
                email.sender,
                email.subject,
                f"{score:.2f}",
                level
            ),
            tags=(tag,)
        )

        self.email_cache[item_id] = {
            "filename": filename,
            "sender": email.sender,
            "subject": email.subject,
            "body": email.text or "(No email body)",
            "risk": f"{score:.2f}%",
            "level": level,
            "details": details,
            "log_path": log_path,
        }

        # Count risk levels
        if level == "Low":
            self.low_count += 1
        elif level == "Medium":
            self.medium_count += 1
        elif level == "High":
            self.high_count += 1



    def write_log_file(self, filename, final_score, level, details):
        log_folder = "Finished Email Scans"
        os.makedirs(log_folder, exist_ok=True)

        base_name = os.path.splitext(os.path.basename(filename))[0]
        log_file_path = os.path.join(log_folder, f"{base_name}.txt")

        with open(log_file_path, "w", encoding="utf-8") as f:
            f.write(f"File: {filename}\n")
            f.write(f"Final Risk: {final_score}\n")
            f.write(f"Level: {level}\n")
            f.write("=" * 60 + "\n\n")

            for key, value in details.items():
                f.write(f"[{key}]\n")

                if isinstance(value, dict):
                    for k, v in value.items():
                        f.write(f"  {k}: {v}\n")

                elif isinstance(value, list):
                    for item in value:
                        f.write(f"  - {item}\n")

                else:
                    f.write(f"  {value}\n")

                f.write("\n")

        return log_file_path


    def clear_logs(self):
        log_folder = "Finished Email Scans"

        if not os.path.exists(log_folder):
            messagebox.showinfo("Info", "No log folder found.")
            return

        confirm = messagebox.askyesno(
            "Confirm Delete",
            "Are you sure you want to delete ALL log files?"
        )

        if not confirm:
            return

        deleted_count = 0

        for file in os.listdir(log_folder):
            file_path = os.path.join(log_folder, file)

            if os.path.isfile(file_path):
                try:
                    os.remove(file_path)
                    deleted_count += 1
                except Exception as e:
                    print(f"Failed to delete {file_path}: {e}")

        messagebox.showinfo(
            "Logs Cleared",
            f"Deleted {deleted_count} log file(s)."
        )


    def show_pie_chart(self):
        total = self.low_count + self.medium_count + self.high_count
        if total == 0:
            return

        # Clear previous chart or text
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        # Create a frame inside chart_frame to hold both chart and legend
        content_frame = tk.Frame(self.chart_frame)
        content_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # --- Pie chart ---
        labels = []
        sizes = []
        colors = []
        explode = []

        if self.low_count > 0:
            labels.append(f"Low ({self.low_count})")
            sizes.append(self.low_count)
            colors.append("#28a745")
            explode.append(0.03)

        if self.medium_count > 0:
            labels.append(f"Medium ({self.medium_count})")
            sizes.append(self.medium_count)
            colors.append("#ffc107")
            explode.append(0.03)

        if self.high_count > 0:
            labels.append(f"High ({self.high_count})")
            sizes.append(self.high_count)
            colors.append("#dc3545")
            explode.append(0.03)

        fig = Figure(figsize=(4, 4), dpi=100)
        ax = fig.add_subplot(111)
        ax.pie(
            sizes,
            labels=None,  # hide labels on slices
            autopct="%1.1f%%",
            startangle=90,
            colors=colors,
            explode=explode,
            pctdistance=0.8
        )
        ax.set_title("Email Risk Distribution")

        # Embed matplotlib figure into left side of frame
        pie_canvas = FigureCanvasTkAgg(fig, master=content_frame)
        pie_canvas.draw()
        pie_canvas.get_tk_widget().pack(side="left", fill="both", expand=True, padx=(0,10))

        # --- Text legend on right side ---
        summary_text = tk.Text(content_frame, width=25, wrap="word")
        summary_text.pack(side="left", fill="both", expand=False)

        summary_text.insert("end", "Email Risk Summary\n")
        summary_text.insert("end", "="*30 + "\n\n")

        def format_line(label, count, color):
            percent = (count / total) * 100
            return f"{label}: {count} ({percent:.1f}%)\n"

        if self.low_count > 0:
            summary_text.insert("end", format_line("Low Risk", self.low_count, "#28a745"))
        if self.medium_count > 0:
            summary_text.insert("end", format_line("Medium Risk", self.medium_count, "#ffc107"))
        if self.high_count > 0:
            summary_text.insert("end", format_line("High Risk", self.high_count, "#dc3545"))

        summary_text.config(state="disabled", font=("Arial", 12))

        # Save canvas reference so it can be destroyed next time
        self.chart_canvas = pie_canvas



    @staticmethod
    def risk_level(score):
        if score < 15:
            return "Low", "low"
        elif score < 51:
            return "Medium", "medium"
        else:
            return "High", "high"


if __name__ == "__main__":    
    app = EmailScannerGUI()
    app.mainloop()

