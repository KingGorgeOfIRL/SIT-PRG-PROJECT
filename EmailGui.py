import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import threading

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

        # variables for canceling the scan
        self.cancel_event = threading.Event()
        self.total_emails = 0
        self.processed_emails = 0

        # Variable for offline checkbox 
        self.offline_mode = tk.BooleanVar(value=False)
        self.protocol("WM_DELETE_WINDOW", self.on_close)



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
            command=self.start_scan
        ).pack(side="right")

        tk.Checkbutton(
            top_frame,
            text="Offline mode (no internet)",
            variable=self.offline_mode,
            command=self.toggle_offline_mode
        ).pack(side="right", padx=10)


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

        self.cancel_button = tk.Button(
            self.loading_frame,
            text="Cancel",
            command=self.cancel_scan,
            bg="#c0392b",
            fg="white"
        )

        self.loading_label.pack(pady=10)
        self.progress.pack(pady=5)
        self.progress_text.pack()
        self.cancel_button.pack(pady=10)

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



    def scan_folder(self):
        folder = self.folder_path.get()
        all_files = [f for f in os.listdir(folder) if f.lower().endswith(".eml")]

        if not all_files:
            messagebox.showinfo("Info", "No .eml files found")
            return

        for filename in all_files:
            try:
                path = os.path.join(folder, filename)
                email = Email(path)

                (
                    doc_score,
                    url_score,
                    email_score,
                    lang_score,
                    attachment_flag,
                    url_flag
                ) = scoringSystem(email)

                # Final weighted score (used the same formula-ish in EmailScore.py)
                if not attachment_flag and not url_flag:
                    final_score = lang_score * 0.45 + email_score * 0.55
                elif not attachment_flag and url_flag:
                    final_score = (
                        lang_score * 0.35 +
                        email_score * 0.40 +
                        url_score * 0.25
                    )
                else:
                    final_score = (
                        lang_score * 0.15 +
                        email_score * 0.35 +
                        url_score * 0.25 +
                        doc_score * 0.25
                    )

                level, tag = self.risk_level(final_score)

                item_id = self.tree.insert(
                    "",
                    "end",
                    values=(
                        filename,
                        email.sender,
                        email.subject,
                        f"{final_score:.2f}",
                        level
                    ),
                    tags=(tag,)
                )

                # --- Get extra data, URLs and Attachments ---
                urls = []
                attachments = []

                try:
                    # URLs
                    url_results = get_urlCheck_scores(email)
                    if isinstance(url_results, dict):
                        urls = list(url_results.keys())

                    # Attachments
                    doc_results = get_docChecking_scores(email)
                    if isinstance(doc_results, dict):
                        attachments = list(doc_results.keys())

                except Exception:
                    pass


                self.email_cache[item_id] = {
                    "filename": filename,
                    "sender": email.sender,
                    "subject": email.subject,
                    "body": email.text or "(No email body)",
                    "risk": f"{final_score:.2f}%",
                    "level": level,
                    "urls": urls,
                    "attachments": attachments
                }

            except Exception as e:
                print(f"Error scanning {filename}: {e}")


    def scan_folder_worker(self, all_files):
        folder = self.folder_path.get()

        for filename in all_files:
            if self.cancel_event.is_set():
                break

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
                    url_flag
                ) = scoringSystem(email)

                if not attachment_flag and not url_flag:
                    final_score = lang_score * 0.45 + email_score * 0.55
                elif not attachment_flag and url_flag:
                    final_score = (
                        lang_score * 0.35 +
                        email_score * 0.40 +
                        url_score * 0.25
                    )
                else:
                    final_score = (
                        lang_score * 0.15 +
                        email_score * 0.35 +
                        url_score * 0.25 +
                        doc_score * 0.25
                    )

                level, tag = self.risk_level(final_score)

                self.after(
                    0,
                    self.add_result_row,
                    filename,
                    email,
                    final_score,
                    level,
                    tag
                )

            except Exception as e:
                print(f"Error scanning {filename}: {e}")

            self.processed_emails += 1
            self.after(0, self.update_progress)

        self.after(0, self.hide_loading)


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
        if self.cancel_event.is_set():
            self.after(0, self.hide_loading)
            return

        
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
                url_flag
            ) = scoringSystem(email)

            if not attachment_flag and not url_flag:
                final_score = lang_score * 0.45 + email_score * 0.55
            elif not attachment_flag and url_flag:
                final_score = (
                    lang_score * 0.35 +
                    email_score * 0.40 +
                    url_score * 0.25
                )
            else:
                final_score = (
                    lang_score * 0.15 +
                    email_score * 0.35 +
                    url_score * 0.25 +
                    doc_score * 0.25
                )

            level, tag = self.risk_level(final_score)

            self.after(
                0,
                self.add_result_row,
                os.path.basename(file_path),
                email,
                final_score,
                level,
                tag
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
        self.highlight_suspicious_words(body_text, data["body"])
        body_text.config(state="disabled")



    def highlight_suspicious_words(self, text_widget, body_text):
        try:
            matrix = init_keyword_matrix()
            suspicious_words = set()

            for category in matrix.values():
                for word in category:
                    suspicious_words.add(word.lower())

            for word in suspicious_words:
                start = "1.0"
                while True:
                    pos = text_widget.search(word, start, stopindex="end", nocase=True)
                    if not pos:
                        break

                    end = f"{pos}+{len(word)}c"
                    text_widget.tag_add("suspicious", pos, end)
                    start = end

            text_widget.tag_config(
                "suspicious",
                background="#fff3cd",
                foreground="black"
            )

        except Exception:
            pass


    def show_loading(self, total):
        self.total_emails = total
        self.processed_emails = 0
        self.cancel_event.clear()

        self.progress["maximum"] = total
        self.progress["value"] = 0
        self.progress_text.config(text=f"0 / {total}")

        self.loading_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.update_idletasks()


    def hide_loading(self):
        disable_offline_mode()
        self.loading_frame.place_forget()


    def cancel_scan(self):
        self.cancel_event.set()
        self.loading_label.config(text="Cancelling…")


    def update_progress(self):
        self.progress["value"] = self.processed_emails
        self.progress_text.config(
            text=f"{self.processed_emails} / {self.total_emails}"
        )


    def add_result_row(self, filename, email, score, level, tag):
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
            "urls": email.urls,
            "attachments": email.attachment_header
        }

            # Write log file
        self.write_log_file(
            filename,
            f"{score:.2f}%",
            level,
            email.urls,
            email.attachment_header
        )

            # --- Write log file for this email ---
        self.write_log_file(filename, f"{score:.2f}%", level, email.urls, email.attachment_header)



    def write_log_file(self, filename, risk, level, urls=None, attachments=None):
        log_folder = "Finished Email Scans"
        # Creates the logs folder if missing
        os.makedirs(log_folder, exist_ok=True)

        base_name = os.path.splitext(os.path.basename(filename))[0]
        log_file_path = os.path.join(log_folder, f"{base_name}.txt")

        with open(log_file_path, "w", encoding="utf-8") as f:
            f.write(f"File: {filename}\n")
            f.write(f"Risk: {risk}\n")
            f.write(f"Level: {level}\n")
            if urls:
                f.write(f"URLs: {', '.join(urls)}\n")
            if attachments:
                f.write(f"Attachments: {', '.join(a['filename'] for a in attachments)}\n")



    @staticmethod
    def risk_level(score):
        if score < 10:
            return "Low", "low"
        elif score < 50:
            return "Medium", "medium"
        else:
            return "High", "high"


if __name__ == "__main__":
    app = EmailScannerGUI()
    app.mainloop()
