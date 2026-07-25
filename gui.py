"""
Point-and-click GUI for File Magic Identifier. No command line needed.

Run with:
    python gui.py            (Windows: double-click also works if .py files
                               are associated with pythonw.exe / python.exe)

Uses only the standard library (tkinter) plus this project's own package,
so no extra pip installs are required beyond what's already in requirements.txt.
"""
from __future__ import annotations

import queue
import threading
import webbrowser
from pathlib import Path
from tkinter import (BooleanVar, StringVar, Tk, filedialog, messagebox, ttk)

from magic_identifier import report
from magic_identifier.scanner import FileResult, scan_directory
from magic_identifier.signatures import load_signatures

DEFAULT_DB = Path(__file__).parent / "data" / "signatures.json"


class MagicIdentifierGUI:
    def __init__(self, root: Tk):
        self.root = root
        root.title("File Magic Identifier")
        root.geometry("980x600")

        self.folder = StringVar(value="")
        self.do_hash = BooleanVar(value=True)
        self.do_embedded = BooleanVar(value=True)
        self.filter_mode = StringVar(value="All files")
        self.status = StringVar(value="Choose a folder to scan.")

        self.results: list[FileResult] = []
        self._msg_queue: "queue.Queue[tuple]" = queue.Queue()
        self._scanning = False

        self._build_layout()
        self.root.after(100, self._poll_queue)

    # ---------------------------------------------------------------- UI

    def _build_layout(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Folder to scan:").grid(row=0, column=0, sticky="w")
        entry = ttk.Entry(top, textvariable=self.folder, width=70)
        entry.grid(row=0, column=1, padx=5, sticky="we")
        ttk.Button(top, text="Browse...", command=self._browse).grid(row=0, column=2)

        opts = ttk.Frame(top)
        opts.grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Checkbutton(opts, text="Compute MD5/SHA-256 hashes", variable=self.do_hash).pack(side="left", padx=(0, 15))
        ttk.Checkbutton(opts, text="Search for embedded files", variable=self.do_embedded).pack(side="left", padx=(0, 15))
        ttk.Label(opts, text="Show:").pack(side="left", padx=(0, 4))
        filter_box = ttk.Combobox(
            opts, textvariable=self.filter_mode, state="readonly", width=22,
            values=["All files", "Mismatches only", "Unknown only", "Mismatches + Unknown"],
        )
        filter_box.pack(side="left")
        filter_box.bind("<<ComboboxSelected>>", lambda e: self._refresh_table())

        actions = ttk.Frame(top)
        actions.grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.scan_btn = ttk.Button(actions, text="Scan Folder", command=self._start_scan)
        self.scan_btn.pack(side="left")
        ttk.Button(actions, text="Export HTML Report...", command=lambda: self._export("html")).pack(side="left", padx=6)
        ttk.Button(actions, text="Export CSV...", command=lambda: self._export("csv")).pack(side="left")
        ttk.Button(actions, text="Export JSON...", command=lambda: self._export("json")).pack(side="left", padx=6)
        ttk.Label(actions, text="(exports use the current \"Show:\" filter)",
                  foreground="#666666").pack(side="left", padx=(10, 0))

        top.columnconfigure(1, weight=1)

        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(4, 0))

        ttk.Label(self.root, textvariable=self.status).pack(anchor="w", padx=10, pady=4)

        # Results table
        columns = ("path", "type", "conf", "ext", "mismatch", "notes")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        headings = {"path": "Path", "type": "Detected Type", "conf": "Conf.",
                    "ext": "Ext.", "mismatch": "Mismatch", "notes": "Embedded / Notes"}
        widths = {"path": 340, "type": 170, "conf": 55, "ext": 55, "mismatch": 80, "notes": 230}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")
        self.tree.tag_configure("mismatch", background="#ffdddd")
        self.tree.tag_configure("unknown", foreground="#888888")

        vsb = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        vsb.pack(side="right", fill="y", pady=10)

    # ------------------------------------------------------------ actions

    def _browse(self):
        chosen = filedialog.askdirectory(title="Choose a folder to scan")
        if chosen:
            self.folder.set(chosen)

    def _start_scan(self):
        if self._scanning:
            return
        folder = self.folder.get().strip()
        if not folder or not Path(folder).is_dir():
            messagebox.showerror("File Magic Identifier", "Please choose a valid folder first.")
            return

        try:
            sigs = load_signatures(str(DEFAULT_DB))
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("File Magic Identifier", f"Could not load signature database:\n{e}")
            return

        self._scanning = True
        self.scan_btn.config(state="disabled")
        self.progress["value"] = 0
        self.status.set("Scanning...")
        self.tree.delete(*self.tree.get_children())

        thread = threading.Thread(
            target=self._run_scan, args=(folder, sigs), daemon=True
        )
        thread.start()

    def _run_scan(self, folder, sigs):
        def on_progress(done, total):
            self._msg_queue.put(("progress", done, total))

        try:
            results = scan_directory(
                folder, sigs,
                do_hash=self.do_hash.get(),
                do_embedded=self.do_embedded.get(),
                progress_callback=on_progress,
            )
            self._msg_queue.put(("done", results))
        except Exception as e:  # noqa: BLE001
            self._msg_queue.put(("error", str(e)))

    def _poll_queue(self):
        try:
            while True:
                msg = self._msg_queue.get_nowait()
                if msg[0] == "progress":
                    _, done, total = msg
                    self.progress["maximum"] = max(total, 1)
                    self.progress["value"] = done
                    self.status.set(f"Scanning... {done}/{total} files")
                elif msg[0] == "done":
                    self.results = msg[1]
                    self._scanning = False
                    self.scan_btn.config(state="normal")
                    self._refresh_table()
                elif msg[0] == "error":
                    self._scanning = False
                    self.scan_btn.config(state="normal")
                    self.status.set("Scan failed.")
                    messagebox.showerror("File Magic Identifier", f"Scan failed:\n{msg[1]}")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _filtered_rows(self) -> list[FileResult]:
        mode = self.filter_mode.get()
        if mode == "Mismatches only":
            return [r for r in self.results if r.mismatch]
        if mode == "Unknown only":
            return [r for r in self.results if r.detected_type == "Unknown"]
        if mode == "Mismatches + Unknown":
            return [r for r in self.results if r.mismatch or r.detected_type == "Unknown"]
        return list(self.results)

    def _refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        rows = self._filtered_rows()
        for r in rows:
            notes = ", ".join(r.embedded_findings) if r.embedded_findings else (r.error or "")
            tag = "mismatch" if r.mismatch else ("unknown" if r.detected_type == "Unknown" else "")
            self.tree.insert("", "end", values=(
                r.path, r.detected_type, f"{r.confidence:.0%}", r.extension,
                "YES" if r.mismatch else "", notes,
            ), tags=(tag,) if tag else ())
        if self.results:
            total_mismatch = sum(1 for r in self.results if r.mismatch)
            total_unknown = sum(1 for r in self.results if r.detected_type == "Unknown")
            self.status.set(
                f"{len(self.results)} files scanned, {total_mismatch} mismatch(es), "
                f"{total_unknown} unknown -- showing {len(rows)} row(s) ({self.filter_mode.get()})."
            )

    def _export(self, fmt: str):
        if not self.results:
            messagebox.showinfo("File Magic Identifier", "Run a scan first.")
            return

        rows = self._filtered_rows()
        if not rows:
            messagebox.showinfo(
                "File Magic Identifier",
                f"No files match the current filter (\"{self.filter_mode.get()}\") -- nothing to export.\n"
                "Change the \"Show:\" dropdown and try again.",
            )
            return

        ext_map = {"html": ".html", "csv": ".csv", "json": ".json"}
        suffix_map = {
            "All files": "full",
            "Mismatches only": "mismatches",
            "Unknown only": "unknown",
            "Mismatches + Unknown": "mismatches_and_unknown",
        }
        suffix = suffix_map[self.filter_mode.get()]

        # On Windows, native save dialogs can sometimes open behind the main
        # window if it doesn't have focus. Force this window to the front
        # first so the dialog is never "invisible".
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.after_idle(self.root.attributes, "-topmost", False)

        path = filedialog.asksaveasfilename(
            parent=self.root,
            title=f"Save {fmt.upper()} report ({self.filter_mode.get()}) as...",
            defaultextension=ext_map[fmt],
            filetypes=[(f"{fmt.upper()} files", f"*{ext_map[fmt]}"), ("All files", "*.*")],
            initialfile=f"magic_identifier_report_{suffix}{ext_map[fmt]}",
        )
        if not path:
            self.status.set("Export cancelled.")
            return

        try:
            if fmt == "html":
                report.export_html(rows, path)
            elif fmt == "csv":
                report.export_csv(rows, path)
            else:
                report.export_json(rows, path)
        except Exception as e:  # noqa: BLE001 - show the real error instead of failing silently
            import traceback
            messagebox.showerror(
                "File Magic Identifier",
                f"Could not write {fmt.upper()} report to:\n{path}\n\n{type(e).__name__}: {e}",
            )
            self.status.set(f"Export failed: {e}")
            traceback.print_exc()
            return

        self.status.set(f"Saved {fmt.upper()} report ({len(rows)} rows, {self.filter_mode.get()}) to {path}")
        if fmt == "html" and messagebox.askyesno("File Magic Identifier", "Report saved. Open it now?"):
            webbrowser.open(f"file://{Path(path).resolve()}")
        else:
            messagebox.showinfo(
                "File Magic Identifier",
                f"Report saved to:\n{path}\n\n({len(rows)} rows -- {self.filter_mode.get()})",
            )


def main():
    root = Tk()
    MagicIdentifierGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
