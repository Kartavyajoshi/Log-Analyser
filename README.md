"""Advanced desktop interface for Log-Analyser."""

from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .analyzer import AnalysisReport, analyze_text


class LogAnalyzerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Log-Analyser Pro")
        self.geometry("1200x760")
        self.minsize(980, 620)
        self.current_path: Path | None = None
        self.report: AnalysisReport | None = None
        self.live_tail_active = False
        self._tail_after_id: str | None = None
        self.dark_mode = True
        self._build_ui()
        self._apply_theme()

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        toolbar = ttk.Frame(self, padding=(12, 10, 12, 8))
        toolbar.grid(row=0, column=0, sticky="ew")
        toolbar.columnconfigure(4, weight=1)

        ttk.Button(toolbar, text="Open log file", command=self.open_file).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(toolbar, text="Analyze", command=self.analyze).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(toolbar, text="Export JSON", command=self.export_json).grid(row=0, column=2, padx=(0, 8))
        ttk.Button(toolbar, text="Toggle theme", command=self.toggle_theme).grid(row=0, column=3, padx=(0, 8))
        self.file_label = ttk.Label(toolbar, text="No file selected")
        self.file_label.grid(row=0, column=4, sticky="w")

        self.main = ttk.Notebook(self)
        self.main.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 8))

        editor_frame = ttk.Frame(self.main, padding=8)
        editor_frame.grid_columnconfigure(0, weight=1)
        editor_frame.grid_rowconfigure(0, weight=1)
        self.input_text = tk.Text(editor_frame, wrap="none", undo=True, height=20)
        self.input_text.grid(row=0, column=0, sticky="nsew")
        editor_scroll_y = ttk.Scrollbar(editor_frame, orient="vertical", command=self.input_text.yview)
        editor_scroll_y.grid(row=0, column=1, sticky="ns")
        editor_scroll_x = ttk.Scrollbar(editor_frame, orient="horizontal", command=self.input_text.xview)
        editor_scroll_x.grid(row=1, column=0, sticky="ew")
        self.input_text.configure(yscrollcommand=editor_scroll_y.set, xscrollcommand=editor_scroll_x.set)
        self.main.add(editor_frame, text="Editor")

        dashboard_frame = ttk.Frame(self.main, padding=10)
        dashboard_frame.grid_columnconfigure(0, weight=1)
        dashboard_frame.grid_rowconfigure(1, weight=1)

        stat_frame = ttk.Frame(dashboard_frame)
        stat_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        for idx in range(5):
            stat_frame.grid_columnconfigure(idx, weight=1)

        self.stat_total = ttk.Label(stat_frame, text="0\nTotal lines", font=("Segoe UI", 11, "bold"), anchor="center")
        self.stat_total.grid(row=0, column=0, sticky="nsew", padx=5, pady=3)
        self.stat_events = ttk.Label(stat_frame, text="0\nSuspicious", font=("Segoe UI", 11, "bold"), anchor="center")
        self.stat_events.grid(row=0, column=1, sticky="nsew", padx=5, pady=3)
        self.stat_ips = ttk.Label(stat_frame, text="0\nUnique IPs", font=("Segoe UI", 11, "bold"), anchor="center")
        self.stat_ips.grid(row=0, column=2, sticky="nsew", padx=5, pady=3)
        self.stat_levels = ttk.Label(stat_frame, text="0\nLevels", font=("Segoe UI", 11, "bold"), anchor="center")
        self.stat_levels.grid(row=0, column=3, sticky="nsew", padx=5, pady=3)
        self.stat_top = ttk.Label(stat_frame, text="N/A\nTop error", font=("Segoe UI", 11, "bold"), anchor="center")
        self.stat_top.grid(row=0, column=4, sticky="nsew", padx=5, pady=3)

        control_frame = ttk.Frame(dashboard_frame)
        control_frame.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(control_frame, text="Search alerts").grid(row=0, column=0, padx=(0, 6), sticky="w")
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(control_frame, textvariable=self.search_var)
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8))
        self.search_entry.bind("<Return>", lambda _event: self.apply_filter())
        ttk.Button(control_frame, text="Filter", command=self.apply_filter).grid(row=0, column=2, padx=(0, 8))
        ttk.Button(control_frame, text="Clear", command=self.clear_filter).grid(row=0, column=3)
        control_frame.grid_columnconfigure(1, weight=1)

        chart_frame = ttk.LabelFrame(dashboard_frame, text="Level distribution")
        chart_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        chart_frame.grid_columnconfigure(0, weight=1)
        chart_frame.grid_rowconfigure(0, weight=1)
        self.chart_canvas = tk.Canvas(chart_frame, height=180, background="#1f1f1f")
        self.chart_canvas.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        table_frame = ttk.LabelFrame(dashboard_frame, text="Suspicious events")
        table_frame.grid(row=3, column=0, sticky="nsew")
        self.alert_table = ttk.Treeview(table_frame, columns=("line", "level", "message", "ip"), show="headings")
        self.alert_table.heading("line", text="Line")
        self.alert_table.heading("level", text="Level")
        self.alert_table.heading("message", text="Message")
        self.alert_table.heading("ip", text="IP")
        self.alert_table.column("line", width=70, anchor="center")
        self.alert_table.column("level", width=90, anchor="center")
        self.alert_table.column("message", width=500)
        self.alert_table.column("ip", width=120)
        self.alert_table.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        table_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.alert_table.yview)
        table_scroll.grid(row=0, column=1, sticky="ns")
        self.alert_table.configure(yscrollcommand=table_scroll.set)
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        self.main.add(dashboard_frame, text="Dashboard")

        report_frame = ttk.Frame(self.main, padding=8)
        report_frame.grid_columnconfigure(0, weight=1)
        report_frame.grid_rowconfigure(0, weight=1)
        self.result_text = tk.Text(report_frame, wrap="none", state="disabled")
        self.result_text.grid(row=0, column=0, sticky="nsew")
        report_scroll_y = ttk.Scrollbar(report_frame, orient="vertical", command=self.result_text.yview)
        report_scroll_y.grid(row=0, column=1, sticky="ns")
        report_scroll_x = ttk.Scrollbar(report_frame, orient="horizontal", command=self.result_text.xview)
        report_scroll_x.grid(row=1, column=0, sticky="ew")
        self.result_text.configure(yscrollcommand=report_scroll_y.set, xscrollcommand=report_scroll_x.set)
        self.main.add(report_frame, text="Report")

        self.status = ttk.Label(self, text="Open a log file or paste log content, then choose Analyze.", relief="sunken", anchor="w")
        self.status.grid(row=2, column=0, sticky="ew")

    def _apply_theme(self) -> None:
        if self.dark_mode:
            bg = "#101418"
            fg = "#e6eaf0"
            panel = "#1a222b"
            accent = "#2b7fff"
            danger = "#f55151"
            warning = "#ffb000"
            success = "#30c48d"
            text = "#e6eaf0"
            canvas_bg = "#1d252d"
        else:
            bg = "#f5f7fb"
            fg = "#1e2430"
            panel = "#ffffff"
            accent = "#2b7fff"
            danger = "#d92d20"
            warning = "#d97706"
            success = "#0f9f6e"
            text = "#1e2430"
            canvas_bg = "#edf2f7"

        self.configure(bg=bg)
        for widget in self.winfo_children():
            try:
                widget.configure(bg=bg)
            except Exception:
                pass
        self.input_text.configure(bg=panel, fg=text, insertbackground=text)
        self.result_text.configure(bg=panel, fg=text, insertbackground=text)
        self.chart_canvas.configure(background=canvas_bg)
        for child in [self.stat_total, self.stat_events, self.stat_ips, self.stat_levels, self.stat_top]:
            child.configure(background=panel, foreground=fg)
        self.file_label.configure(foreground=fg)
        self.status.configure(background=panel, foreground=fg)

        self.alert_table.tag_configure("danger", background="#5c1f1f", foreground="#f5d1d1")
        self.alert_table.tag_configure("warn", background="#4d3b12", foreground="#f7e2a0")
        self.alert_table.tag_configure("info", background="#173b31", foreground="#d3f7eb")

    def toggle_theme(self) -> None:
        self.dark_mode = not self.dark_mode
        self._apply_theme()

    def open_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select a log file",
            filetypes=[("Log files", "*.log *.txt *.out *.*"), ("All files", "*")],
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
            self.main.select(0)
        except OSError as exc:
            messagebox.showerror("Could not open file", str(exc))

    def analyze(self) -> None:
        content = self.input_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("No log data", "Open a log file or paste log content first.")
            return
        self.report = analyze_text(content)
        self._update_dashboard()
        self._set_result(self._format_report(self.report))
        self.status.configure(
            text=f"Analyzed {self.report.total_lines} lines and found {len(self.report.suspicious_events)} suspicious events."
        )
        self.main.select(1)

    def _update_dashboard(self) -> None:
        if self.report is None:
            return

        self.stat_total.configure(text=f"{self.report.total_lines}\nTotal lines")
        self.stat_events.configure(text=f"{len(self.report.suspicious_events)}\nSuspicious")
        self.stat_ips.configure(text=f"{len(self.report.unique_ips)}\nUnique IPs")
        self.stat_levels.configure(text=f"{len(self.report.levels)}\nLevels")
        self.stat_top.configure(text=f"{self.report.top_errors[0][0][:12] if self.report.top_errors else 'N/A'}\nTop error")

        self._draw_chart(self.report.levels)
        self._populate_alert_table(self.report.suspicious_events)

    def _draw_chart(self, level_map: dict[str, int]) -> None:
        self.chart_canvas.delete("all")
        if not level_map:
            self.chart_canvas.create_text(180, 90, text="No level data", fill="#dfe6f5")
            return

        max_value = max(level_map.values()) or 1
        width = 700
        height = 170
        margin_left = 30
        margin_right = 22
        margin_top = 20
        margin_bottom = 24
        cols = len(level_map)
        bar_gap = 18
        bar_width = max(34, (width - margin_left - margin_right - (cols - 1) * bar_gap) // cols)

        x_start = margin_left
        for idx, (label, value) in enumerate(sorted(level_map.items())):
            bar_height = (value / max_value) * (height - margin_top - margin_bottom)
            x0 = x_start + idx * (bar_width + bar_gap)
            y0 = height - margin_bottom
            y1 = y0 - bar_height
            fill = {
                "INFO": "#40c4ff",
                "WARNING": "#ffc857",
                "ERROR": "#ff6b6b",
                "CRITICAL": "#cb2d3e",
                "DEBUG": "#7ae582",
                "TRACE": "#9f7aea",
            }.get(label.upper(), "#7aa2ff")
            self.chart_canvas.create_rectangle(x0, y0, x0 + bar_width, y1, fill=fill, outline="")
            self.chart_canvas.create_text(x0 + bar_width / 2, y0 + 14, text=f"{label[:4]}", fill="#dfe6f5")
            self.chart_canvas.create_text(x0 + bar_width / 2, y1 - 10, text=str(value), fill="#dfe6f5")

    def _populate_alert_table(self, alerts: list[dict[str, object]]) -> None:
        for row in self.alert_table.get_children():
            self.alert_table.delete(row)

        for alert in alerts:
            level = str(alert.get("level", "INFO")).upper()
            tag = "danger" if "ERROR" in level or "CRITICAL" in level else "warn" if "WARNING" in level else "info"
            self.alert_table.insert(
                "",
                tk.END,
                values=(
                    alert.get("line_number", "-"),
                    level,
                    str(alert.get("message", ""))[:180],
                    alert.get("ip") or "-",
                ),
                tags=(tag,),
            )

    def apply_filter(self) -> None:
        if self.report is None:
            return
        query = self.search_var.get().strip().lower()
        if not query:
            self._populate_alert_table(self.report.suspicious_events)
            return

        filtered = [
            alert for alert in self.report.suspicious_events
            if query in str(alert.get("message", "")).lower() or query in str(alert.get("ip") or "").lower()
        ]
        self._populate_alert_table(filtered)

    def clear_filter(self) -> None:
        self.search_var.set("")
        if self.report is not None:
            self._populate_alert_table(self.report.suspicious_events)

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
