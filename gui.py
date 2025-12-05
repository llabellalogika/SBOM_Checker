import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

from core.report_generator import HEADERS
from core.sbom_reader import carica_sbom_generico, estrai_librerie
from core.version_resolver import risolvi_versioni


class SBOMCheckerGUI:
    BG_COLOR = "#f6fbff"
    PANEL_COLOR = "#ffffff"
    ACCENT_COLOR = "#3da9ff"
    ALERT_COLOR = "#e86b5d"
    TEXT_COLOR = "#1f2a44"
    MUTED_TEXT_COLOR = "#60708f"
    SIDEBAR_COLOR = "#e8f0fb"  # aggiunta: colore barra laterale

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("SBOM Checker - GUI")
        self.root.configure(bg=self.BG_COLOR)
        self.root.geometry("960x620")

        self._configure_style()
        self._build_layout()

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
            relief="flat",
        )
        style.configure(
            "Treeview.Heading",
            background=self.BG_COLOR,
            foreground=self.TEXT_COLOR,
            font=("Inter", 10, "bold"),
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", "#e7f4ff")],
            foreground=[("selected", self.TEXT_COLOR)],
        )

        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure(
            "TButton",
            font=("Inter", 10, "bold"),
            padding=(14, 8),
            borderwidth=0,
            relief="flat",
            background=self.ACCENT_COLOR,
            foreground="#ffffff",
        )
        style.map(
            "TButton",
            background=[("active", "#1f8ed6")],
            relief=[("pressed", "flat")],
        )
        style.configure(
            "TLabel",
            background=self.BG_COLOR,
            foreground=self.TEXT_COLOR,
            font=("Inter", 11),
        )
        style.configure(
            "Card.TFrame",
            background=self.PANEL_COLOR,
            borderwidth=0,
            relief="flat",
        )
        style.configure(
            "CardHeading.TLabel",
            font=("Segoe UI", 11, "bold"),
            foreground=self.TEXT_COLOR,
        )

    def _build_sidebar(self) -> None:
        spacer = tk.Frame(self.sidebar, bg=self.SIDEBAR_COLOR, height=24)
        spacer.pack()

        menu_button = tk.Button(
            self.sidebar,
            text="☰",
            command=self._open_menu,
            font=("Segoe UI", 16, "bold"),
            fg=self.TEXT_COLOR,
            bg=self.SIDEBAR_COLOR,
            activebackground=self.PANEL_COLOR,
            activeforeground=self.ACCENT_COLOR,
            relief="flat",
            bd=0,
            highlightthickness=0,
            cursor="hand2",
            width=3,
            pady=10,
        )
        menu_button.pack(pady=(8, 16))

        accent_bar = tk.Frame(self.sidebar, bg=self.ACCENT_COLOR, width=2)
        accent_bar.pack(fill="y", side="left")

        shortcuts = tk.Frame(self.sidebar, bg=self.SIDEBAR_COLOR)
        shortcuts.pack(fill="both", expand=True)

        for icon, _ in [("🏠", "Dashboard"), ("📄", "Report"), ("🛡️", "Sicurezza")]:
            btn = tk.Button(
                shortcuts,
                text=icon,
                font=("Segoe UI Emoji", 16),
                fg=self.MUTED_TEXT_COLOR,
                bg=self.SIDEBAR_COLOR,
                activebackground=self.PANEL_COLOR,
                activeforeground=self.ACCENT_COLOR,
                relief="flat",
                bd=0,
                highlightthickness=0,
                cursor="hand2",
                pady=10,
            )
            btn.pack(pady=6)

    def _build_layout(self) -> None:
        main_container = tk.Frame(self.root, bg=self.BG_COLOR)
        main_container.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(main_container, bg=self.SIDEBAR_COLOR, width=76)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        self._build_sidebar()

        self.content = tk.Frame(main_container, bg=self.BG_COLOR)
        self.content.pack(side="left", fill="both", expand=True)

        self._build_header()
        self._build_controls()

        self.body = tk.PanedWindow(
            self.content,
            orient=tk.VERTICAL,
            bg=self.BG_COLOR,
            sashwidth=8,
            sashrelief="flat",
            borderwidth=0,
            relief="flat",
            showhandle=False,
        )
        self.body.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self._build_table()
        self._build_notes_panel()
        self.root.after(50, self._set_initial_split)

    def _build_header(self) -> None:
        header = tk.Frame(self.content, bg=self.BG_COLOR)
        header.pack(fill="x", pady=(16, 8), padx=16)

        title = tk.Label(
            header,
            text="Firmware SBOM Checker",
            fg=self.ACCENT_COLOR,
            bg=self.BG_COLOR,
            font=("Inter", 18, "bold"),
        )
        title.pack(anchor="w")

        subtitle = tk.Label(
            header,
            text="Genera report moderni a partire da file SBOM (.json o .spdx)",
            fg=self.MUTED_TEXT_COLOR,
            bg=self.BG_COLOR,
            font=("Inter", 11),
        )
        subtitle.pack(anchor="w")

    def _open_menu(self) -> None:
        messagebox.showinfo(
            "Menu",
            "Seleziona un file SBOM dalla schermata principale per generare il report.",
        )

    def _build_controls(self) -> None:
        controls = tk.Frame(self.content, bg=self.BG_COLOR)
        controls.pack(fill="x", padx=16, pady=(0, 12))

        left = tk.Frame(controls, bg=self.BG_COLOR)
        left.pack(side="left", padx=(4, 0), pady=8)

        select_btn = ttk.Button(
            left,
            text="Genera report",
            command=self._on_select_file,
            style="TButton",
        )
        select_btn.pack(side="left")

        self.selected_file_label = tk.Label(
            left,
            text="Nessun file selezionato",
            fg=self.MUTED_TEXT_COLOR,
            bg=self.BG_COLOR,
            font=("Segoe UI", 10),
        )
        self.selected_file_label.pack(side="left", padx=12)

        summary = tk.Frame(controls, bg=self.BG_COLOR)
        summary.pack(side="right", padx=8, pady=8)

        self.update_label = tk.Label(
            summary,
            text="",
            fg=self.TEXT_COLOR,
            bg=self.BG_COLOR,
            font=("Segoe UI", 11, "bold"),
        )
        self.update_label.pack(side="right")

    def _build_table(self) -> None:
        table_frame = tk.Frame(self.body, bg=self.BG_COLOR)
        self.body.add(table_frame, minsize=150, stretch="always")

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

        self.tree.tag_configure(
            "needs update", background="#fff2f0", foreground=self.ALERT_COLOR
        )
        self.tree.tag_configure(
            "up-to-date", background="#f2fbf7", foreground="#1b8a5f"
        )
        self.tree.tag_configure(
            "unknown", background="#f7f5ed", foreground="#9c640c"
        )

    def _build_notes_panel(self) -> None:
        notes_frame = tk.LabelFrame(
            self.body,
            text="Note di sicurezza",
            bg=self.PANEL_COLOR,
            fg=self.TEXT_COLOR,
            font=("Inter", 12, "bold"),
        )
        self.body.add(notes_frame, minsize=200, stretch="always")

        self.notes_box = tk.Text(
            notes_frame,  # fix: era notes_container
            height=12,
            bg=self.PANEL_COLOR,
            fg=self.TEXT_COLOR,
            insertbackground=self.TEXT_COLOR,
            font=("Inter", 10),
            relief="flat",
            wrap="word",
            state="disabled",
        )
        self.notes_box.pack(fill="both", expand=True)

    def _set_initial_split(self) -> None:
        """Set the split so that the release notes occupy roughly half the window."""

        self.root.update_idletasks()
        total_height = self.body.winfo_height()
        if total_height <= 0:
            return

        midpoint = total_height // 2
        try:
            self.body.sash_place(0, 0, midpoint)
        except tk.TclError:
            # In rare cases the paned window may not be ready yet; try again shortly.
            self.root.after(50, self._set_initial_split)

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
            messagebox.showerror(
                "Errore", f"Impossibile leggere il file SBOM:\n{exc}"
            )
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
            self.tree.insert(
                "", "end", values=values, tags=(lib.get("status", ""),)
            )

    def _populate_notes(self, data) -> None:
        self.notes_box.config(state="normal")
        self.notes_box.delete("1.0", "end")

        cve_sections = [
            lib
            for lib in data
            if any((rel.get("cve") or "").strip() for rel in lib.get("cve_notes", []))
        ]

        notes_to_print = [lib for lib in data if lib.get("security_notes")]

        if not cve_sections and not notes_to_print:
            self.notes_box.insert(
                "end",
                "Nessun aggiornamento di sicurezza rilevato nelle versioni successive.",
            )
        else:
            if cve_sections:
                self.notes_box.insert("end", "Elenco CVE\n", ("section",))
                for lib in cve_sections:
                    self.notes_box.insert("end", f"{lib['name']}\n", ("title",))
                    for rel in lib.get("cve_notes", []):
                        cve = (rel.get("cve") or "").strip()
                        if not cve:
                            continue
                        version = rel.get("version", "")
                        date = rel.get("release_date") or "data n/a"
                        self.notes_box.insert(
                            "end", f"  - {version} ({date})\n", ("subtitle",)
                        )
                        for line in cve.splitlines():
                            self.notes_box.insert(
                                "end", f"    CVE: {line}\n", ("cve",)
                            )
                    self.notes_box.insert("end", "\n")

            if notes_to_print:
                if cve_sections:
                    self.notes_box.insert("end", "\n")
                self.notes_box.insert("end", "Note di sicurezza\n", ("section",))
                for lib in notes_to_print:
                    self.notes_box.insert("end", f"{lib['name']}\n", ("title",))
                    for rel in lib["security_notes"]:
                        version = rel.get("version", "")
                        date = rel.get("release_date") or "data n/a"
                        notes = rel.get("release_notes") or "Release notes non disponibili."
                        cve = rel.get("cve") or ""
                        self.notes_box.insert(
                            "end", f"  - {version} ({date})\n", ("subtitle",)
                        )
                        for line in notes.splitlines():
                            self.notes_box.insert("end", f"    • {line}\n")
                        if cve:
                            for line in cve.splitlines():
                                self.notes_box.insert(
                                    "end", f"    CVE: {line}\n", ("cve",)
                                )
                    self.notes_box.insert("end", "\n")

        self.notes_box.tag_configure(
            "title", foreground=self.ACCENT_COLOR, font=("Inter", 11, "bold")
        )
        self.notes_box.tag_configure(
            "subtitle",
            foreground=self.MUTED_TEXT_COLOR,
            font=("Inter", 10, "bold"),
        )
        self.notes_box.tag_configure(
            "cve",
            foreground=self.ALERT_COLOR,
            font=("Inter", 10, "bold"),
        )
        self.notes_box.tag_configure(
            "section",
            foreground=self.TEXT_COLOR,
            font=("Inter", 12, "bold"),
        )
        self.notes_box.config(state="disabled")

    def _update_summary(self, data) -> None:
        count_needs_update = sum(
            1 for lib in data if lib.get("status") == "needs update"
        )
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
