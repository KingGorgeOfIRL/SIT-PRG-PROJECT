# 45% Language, 55% email, urls no, attachment no
# 35% Language, 40% email, 25% Url, attachment no
# 15%, language, 35% email, 25% url, 25% attachment


from URLChecking.UrlCheck import UrlCheck
from EmailVerify.main import EmailVerifier, Email

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from email.parser import Parser
from email import policy

def get_docChecking_scores():
    pass


def get_urlCheck_scores():
    # If score is higher than 100 (Maximum score for URLchecking is around 190), flag it as suspicious
    # Note that self.urls.append() is used to add URLs to self.urls, if self.urls is empty self.url_score stays empty and there will be no loop

    email = UrlCheck("Resources\DATASET\story.eml")

    # Gets the dictionary of all the urls(keys) and the scores(values)
    score_dict = email.url_score

    total_score = 0

    # Gets only the scores in the dictionary, and adds them all up
    for scores in score_dict.values():
        scores = int(scores)
        total_score = total_score + scores

    # Gets the percentage score
    overall_percentage = (total_score / 190) * 100

    return overall_percentage



def get_emailVerify_scores():
    # edit_distance() is used for detecting sus typos like g00gle.com instead of google.com (Levenshtein edit distance)
    # To use the EmailVerifier class you need to give normalize_domain() an EmailVerifier object, not a string
    email = Email("Resources/DATASET/Project Proposal.eml")
    verifier = EmailVerifier(email)
    
    result = verifier.run_verification()
    print(result)

    



def get_langAnalysis_scores():
    pass





# print(f"Percentage from UrlCheck : {get_urlCheck_scores()}%")
# print(f"Percentage from DocChecking : {get_docChecking_scores()}%")
# get_emailVerify_scores()



##############################                 End of scores gathering section, start of GUI section                 ###########################################################



# Example results
def analyze_email(file_path):
    return (
        {"Safe": 70, "Suspicious": 30},
        {"Trusted": 50, "Untrusted": 50},
        {"High Risk": 20, "Medium Risk": 50, "Low Risk": 30},
        {"Phishing": 10, "Spam": 20, "Legit": 70}
    )

# Dummy function to extract email content
def get_email_content(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        raw = Parser(policy=policy.default).parse(f)
    subject = raw.get('Subject', '')
    body = ''
    for part in raw.walk():
        if 'text/plain' in part.get_content_type():
            body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
        elif 'text/html' in part.get_content_type():
            body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
    return subject, body

class EmailPieApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Analysis Pie Charts")
        self.root.geometry("1200x600")

        # Top-left: overall risk, top-right: selected chart, right: email content
        self.left_frame = tk.Frame(root)
        self.left_frame.pack(side='left', fill='both', expand=True)

        self.right_frame = tk.Frame(root)
        self.right_frame.pack(side='right', fill='both', expand=True)

        # Dropdown menu for pie charts
        self.chart_names = ["Attachment Validation", "URL Validator", "Email Validator", "Language Analysis"]
        self.current_chart = tk.StringVar()
        self.current_chart.set(self.chart_names[0])
        self.dropdown = tk.OptionMenu(self.left_frame, self.current_chart, *self.chart_names, command=self.update_chart_display)
        self.dropdown.pack(pady=10)

        # Button to select email file
        self.button = tk.Button(self.left_frame, text="Select Email File", command=self.load_email)
        self.button.pack(pady=5)

        # Frame for pie charts
        self.charts_frame = tk.Frame(self.left_frame)
        self.charts_frame.pack(fill='both', expand=True)

        # Overall risk pie chart
        self.fig_overall, self.ax_overall = plt.subplots(figsize=(4,4))
        self.canvas_overall = FigureCanvasTkAgg(self.fig_overall, master=self.charts_frame)
        self.canvas_overall.get_tk_widget().pack(side='left', fill='both', expand=True, padx=5)

        # Selected chart pie chart
        self.fig_chart, self.ax_chart = plt.subplots(figsize=(4,4))
        self.canvas_chart = FigureCanvasTkAgg(self.fig_chart, master=self.charts_frame)
        self.canvas_chart.get_tk_widget().pack(side='left', fill='both', expand=True, padx=5)

        # Email info (right side)
        self.email_filename_label = tk.Label(self.right_frame, text="No email selected", anchor='w')
        self.email_filename_label.pack(fill='x', padx=10, pady=5)

        self.email_content_text = scrolledtext.ScrolledText(self.right_frame, wrap='word')
        self.email_content_text.pack(fill='both', expand=True, padx=10, pady=5)

        # Store chart data
        self.chart_data = [
            {"Safe": 100},
            {"Trusted": 100},
            {"High Risk": 100},
            {"Phishing": 100}
        ]

        # Draw initial charts
        self.draw_chart(0)
        self.draw_overall_chart()

    def load_email(self):
        file_path = filedialog.askopenfilename(filetypes=[("Email files", "*.eml")])
        if file_path:
            # Update chart data
            self.chart_data = analyze_email(file_path)
            self.update_chart_display(self.current_chart.get())
            self.draw_overall_chart()

            # Show filename
            self.email_filename_label.config(text=f"Selected file: {file_path.split('/')[-1]}")

            # Show email content
            subject, body = get_email_content(file_path)
            self.email_content_text.delete(1.0, tk.END)
            self.email_content_text.insert(tk.END, f"Subject: {subject}\n\n{body}")

    def draw_chart(self, index):
        self.ax_chart.clear()
        data = self.chart_data[index]
        labels = list(data.keys())
        sizes = list(data.values())

        # Color mapping
        colors = []
        for label in labels:
            l = label.lower().strip()
            if l in ["safe", "trusted", "legit", "low risk"]:
                colors.append("green")
            elif l in ["medium", "warning", "medium risk"]:
                colors.append("orange")
            elif l in ["untrusted", "suspicious", "high risk", "risk", "phishing", "spam"]:
                colors.append("red")
            else:
                colors.append("gray")

        # Draw pie chart
        wedges, texts, autotexts = self.ax_chart.pie(
            sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors
        )
        self.ax_chart.axis('equal')

        # Set the title inside the pie chart axes
        self.ax_chart.set_title(self.current_chart.get(), fontsize=14, fontweight='bold')

        # Legend below the pie chart
        self.ax_chart.legend(
            wedges,
            [f"{l}: {s}%" for l, s in zip(labels, sizes)],
            title="Legend",
            loc="lower center",
            bbox_to_anchor=(0.5, -0.1),
            ncol=2,
            frameon=False
        )

        self.canvas_chart.draw()

    def draw_overall_chart(self):
        self.ax_overall.clear()
        # Calculate overall risk percentage
        total_scores = {"Safe": 0, "Risk": 0}
        for chart in self.chart_data:
            # Sum "good" vs "bad"
            for key, val in chart.items():
                key_lower = key.lower()
                if key_lower in ["safe", "trusted", "legit", "low risk"]:
                    total_scores["Safe"] += val
                else:
                    total_scores["Risk"] += val

        # Normalize to 100%
        total_sum = total_scores["Safe"] + total_scores["Risk"]
        if total_sum == 0:
            sizes = [50,50]
        else:
            sizes = [total_scores["Safe"] / total_sum * 100, total_scores["Risk"] / total_sum * 100]

        labels = ["Safe", "Risk"]
        colors = ["green", "red"]

        wedges, texts, autotexts = self.ax_overall.pie(
            sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors
        )
        self.ax_overall.axis('equal')
        self.ax_overall.set_title("Overall Risk", fontsize=14, fontweight='bold')
        self.ax_overall.legend(wedges, [f"{legend}: {s:.1f}%" for legend, s in zip(labels, sizes)],
                               title="Legend", loc="lower center", bbox_to_anchor=(0.5, -0.1),
                               ncol=2, frameon=False)

        self.canvas_overall.draw()

    def update_chart_display(self, selected_name):
        index = self.chart_names.index(selected_name)
        self.draw_chart(index)
        self.draw_overall_chart()

if __name__ == "__main__":
    root = tk.Tk()
    app = EmailPieApp(root)
    root.mainloop()


