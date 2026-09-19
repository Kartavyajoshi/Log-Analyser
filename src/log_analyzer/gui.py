"""Tkinter desktop interface for Log-Analyser."""

from __future__ import annotations

import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .analyzer import AnalysisReport, analyze_log_file, analyze_text


class LogAnalyzerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Log-Analyser")
        self.geometry("1100x720")
        self.minsize(820, 560)
        self.current_path: Path | None = None
        self.report: AnalysisReport | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        toolbar = ttk.Frame(self, padding=10)
        toolbar.grid(row=0, column=0, sticky="ew")
        toolbar.columnconfigure(3, weight=1)

        ttk.Button(toolbar, text="Open log file", command=self.open_file).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(toolbar, text="Analyze", command=self.analyze).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(toolbar, text="Export JSON", command=self.export_json).grid(row=0, column=2, padx=(0, 8))
        self.file_label = ttk.Label(toolbar, text="No file selected")
        self.file_label.grid(row=0, column=3, sticky="w")

        notebook = ttk.Notebook(self)
        notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        input_frame = ttk.Frame(notebook, padding=8)
        input_frame.rowconfigure(0, weight=1)
        input_frame.columnconfigure(0, weight=1)
        self.input_text = tk.Text(input_frame, wrap="none", undo=True)
        self.input_text.grid(row=0, column=0, sticky="nsew")
        input_scroll = ttk.Scrollbar(input_frame, orient="vertical", command=self.input_text.yview)
        input_scroll.grid(row=0, column=1, sticky="ns")
        self.input_text.configure(yscrollcommand=input_scroll.set)
        notebook.add(input_frame, text="Log input")

        result_frame = ttk.Frame(notebook, padding=8)
        result_frame.rowconfigure(0, weight=1)
        result_frame.columnconfigure(0, weight=1)
        self.result_text = tk.Text(result_frame, wrap="none", state="disabled")
        self.result_text.grid(row=0, column=0, sticky="nsew")
        result_scroll = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_text.yview)
        result_scroll.grid(row=0, column=1, sticky="ns")
        self.result_text.configure(yscrollcommand=result_scroll.set)
        notebook.add(result_frame, text="Analysis report")

        self.status = ttk.Label(self, text="Open a log file or paste log content, then select Analyze.", relief="sunken", anchor="w")
        self.status.grid(row=2, column=0, sticky="ew")

    def open_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select a log file",
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*")],
        )
        if not filename:
            return
        try:
            path = Path(filename)
            content = path.read_text(encoding="utf-8", errors="replace")
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", content)
            self.current_path = path
            self.file_label.configure(text=str(path))
            self.status.configure(text=f"Loaded {path.name}")
        except OSError as exc:
            messagebox.showerror("Could not open file", str(exc))

    def analyze(self) -> None:
        content = self.input_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("No log data", "Open a log file or paste log content first.")
            return
        self.report = analyze_text(content)
        self._set_result(self._format_report(self.report))
        self.status.configure(text=f"Analyzed {self.report.total_lines} lines and found {len(self.report.suspicious_events)} suspicious events.")

    def export_json(self) -> None:
        if self.report is None:
            messagebox.showwarning("Nothing to export", "Analyze a log before exporting a report.")
            return
        filename = filedialog.asksaveasfilename(
            title="Export analysis report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*")],
        )
        if not filename:
            return
        try:
            Path(filename).write_text(self.report.to_json() + "\n", encoding="utf-8")
            self.status.configure(text=f"Report exported to {filename}")
        except OSError as exc:
            messagebox.showerror("Could not export report", str(exc))

    @staticmethod
    def _format_report(report: AnalysisReport) -> str:
        output = {
            "summary": {
                "total_lines": report.total_lines,
                "parsed_entries": report.parsed_entries,
                "unique_ips": len(report.unique_ips),
                "suspicious_events": len(report.suspicious_events),
            },
            "levels": report.levels,
            "status_codes": report.status_codes,
            "unique_ips": report.unique_ips,
            "suspicious_events": report.suspicious_events,
            "top_errors": [
                {"message": message, "count": count}
                for message, count in report.top_errors
            ],
        }
        return json.dumps(output, indent=2)

    def _set_result(self, value: str) -> None:
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("1.0", value)
        self.result_text.configure(state="disabled")


def run_gui() -> None:
    app = LogAnalyzerApp()
    app.mainloop()
