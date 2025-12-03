import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

from core.report_generator import HEADERS
from core.sbom_reader import carica_sbom_generico, estrai_librerie
from core.version_resolver import risolvi_versioni


class SBOMCheckerGUI:
    BG_COLOR = "#0b132b"
    PANEL_COLOR = "#1c2541"
    ACCENT_COLOR = "#5bc0be"
    ALERT_COLOR = "#ff6b6b"
    TEXT_COLOR = "#e0e6f1"
    MUTED_TEXT_COLOR = "#a7b3d0"

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("SBOM Checker - GUI")
        self.root.configure(bg=self.BG_COLOR)
        self.root.geometry("960x620")

        self._configure_style()
        self._build_header()
        self._build_controls()
        self._build_table()
        self._build_notes_panel()

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=self.PANEL_COLOR,
            fieldbackground=self.PANEL_COLOR,
            foreground=self.TEXT_COLOR,
            rowheight=28,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=self.ACCENT_COLOR,
            foreground=self.BG_COLOR,
            font=("Segoe UI", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", "#22304f")])

        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure(
            "TLabel",
            background=self.BG_COLOR,
            foreground=self.TEXT_COLOR,
            font=("Segoe UI", 11),
        )

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=self.BG_COLOR)
        header.pack(fill="x", pady=(16, 8), padx=16)

        title = tk.Label(
            header,
            text="Firmware SBOM Checker",
            fg=self.ACCENT_COLOR,
            bg=self.BG_COLOR,
            font=("Segoe UI", 18, "bold"),
        )
        title.pack(anchor="w")

        subtitle = tk.Label(
            header,
            text="Seleziona un file SBOM (.json o .spdx) per generare il report",
            fg=self.MUTED_TEXT_COLOR,
            bg=self.BG_COLOR,
            font=("Segoe UI", 11),
        )
        subtitle.pack(anchor="w")

    def _build_controls(self) -> None:
        controls = tk.Frame(self.root, bg=self.BG_COLOR)
        controls.pack(fill="x", padx=16, pady=(0, 12))

        select_btn = ttk.Button(
            controls,
            text="Seleziona SBOM",
            command=self._on_select_file,
            style="Accent.TButton",
        )
        select_btn.pack(side="left")

        self.selected_file_label = tk.Label(
            controls,
            text="Nessun file selezionato",
            fg=self.MUTED_TEXT_COLOR,
            bg=self.BG_COLOR,
            font=("Segoe UI", 10),
        )
        self.selected_file_label.pack(side="left", padx=12)

        self.update_label = tk.Label(
            controls,
            text="",
            fg=self.TEXT_COLOR,
            bg=self.BG_COLOR,
            font=("Segoe UI", 11, "bold"),
        )
        self.update_label.pack(side="right")

    def _build_table(self) -> None:
        table_frame = tk.Frame(self.root, bg=self.BG_COLOR)
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        columns = [h for h in HEADERS]
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center", stretch=True, width=200)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        self.tree.tag_configure("needs update", background="#ffecec", foreground="#c0392b")
        self.tree.tag_configure("up-to-date", background="#e9f7ef", foreground="#1e8449")
        self.tree.tag_configure("unknown", background="#fdf4e3", foreground="#9c640c")

    def _build_notes_panel(self) -> None:
        notes_frame = tk.LabelFrame(
            self.root,
            text="Note di sicurezza",
            bg=self.BG_COLOR,
            fg=self.ACCENT_COLOR,
            labelanchor="nw",
            padx=12,
            pady=8,
        )
        notes_frame.pack(fill="both", expand=False, padx=16, pady=(0, 16))

        self.notes_box = tk.Text(
            notes_frame,
            height=8,
            bg=self.PANEL_COLOR,
            fg=self.TEXT_COLOR,
            insertbackground=self.TEXT_COLOR,
            font=("Consolas", 10),
            relief="flat",
            wrap="word",
            state="disabled",
        )
        self.notes_box.pack(fill="both", expand=True)

    def _on_select_file(self) -> None:
        filepath = filedialog.askopenfilename(
            title="Seleziona un file SBOM",
            filetypes=[("SBOM files", "*.json *.spdx"), ("Tutti i file", "*.*")],
        )
        if not filepath:
            return
        self._render_report(Path(filepath))

    def _render_report(self, path: Path) -> None:
        try:
            comps = carica_sbom_generico(path)
            libs = estrai_librerie(comps)
            data = risolvi_versioni(libs)
        except Exception as exc:
            messagebox.showerror("Errore", f"Impossibile leggere il file SBOM:\n{exc}")
            return

        self.selected_file_label.config(text=path.name, fg=self.TEXT_COLOR)
        self._populate_table(data)
        self._populate_notes(data)
        self._update_summary(data)

    def _populate_table(self, data) -> None:
        self.tree.delete(*self.tree.get_children())
        for lib in data:
            values = (
                lib.get("name", ""),
                lib.get("current", ""),
                lib.get("latest", ""),
                lib.get("security_label", ""),
            )
            self.tree.insert("", "end", values=values, tags=(lib.get("status", ""),))

    def _populate_notes(self, data) -> None:
        self.notes_box.config(state="normal")
        self.notes_box.delete("1.0", "end")

        notes_to_print = [lib for lib in data if lib.get("security_notes")]
        if not notes_to_print:
            self.notes_box.insert("end", "Nessun aggiornamento di sicurezza rilevato nelle versioni successive.")
        else:
            for lib in notes_to_print:
                self.notes_box.insert("end", f"{lib['name']}\n", ("title",))
                for rel in lib["security_notes"]:
                    version = rel.get("version", "")
                    date = rel.get("release_date") or "data n/a"
                    notes = rel.get("release_notes") or "Release notes non disponibili."
                    self.notes_box.insert("end", f"  - {version} ({date})\n", ("subtitle",))
                    for line in notes.splitlines():
                        self.notes_box.insert("end", f"    • {line}\n")
                self.notes_box.insert("end", "\n")

        self.notes_box.tag_configure("title", foreground=self.ACCENT_COLOR, font=("Segoe UI", 11, "bold"))
        self.notes_box.tag_configure("subtitle", foreground=self.MUTED_TEXT_COLOR, font=("Segoe UI", 10, "bold"))
        self.notes_box.config(state="disabled")

    def _update_summary(self, data) -> None:
        count_needs_update = sum(1 for lib in data if lib.get("status") == "needs update")
        if count_needs_update:
            text = f"Librerie da aggiornare: {count_needs_update}"
            color = self.ALERT_COLOR
        else:
            text = "Tutte le librerie risultano aggiornate"
            color = self.ACCENT_COLOR
        self.update_label.config(text=text, fg=color)

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    app = SBOMCheckerGUI()
    app.run()


if __name__ == "__main__":
    main()
