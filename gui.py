import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

from core.db_manager import get_library_names, get_releases_for_library
from core.report_generator import HEADERS
from core.sbom_reader import carica_sbom_generico, estrai_librerie
from core.version_resolver import risolvi_versioni


class SBOMCheckerGUI:
    BG_COLOR = "#f6fbff"
    PANEL_COLOR = "#ffffff"
    ACCENT_COLOR = "#fada5e"
    ALERT_COLOR = "#e86b5d"
    TEXT_COLOR = "#8cb155"
    MUTED_TEXT_COLOR = "#6f7f3a"
    SIDEBAR_COLOR = "#e8f0fb"  # sidebar color

    LIBRARY_LINKS = {
        "FreeRTOS": "https://www.freertos.org/",
        "LwIP": "https://www.nongnu.org/lwip/",
        "FatFs": "http://elm-chan.org/fsw/ff/00index_e.html",
        "mbedTLS": "https://github.com/Mbed-TLS/mbedtls",
        "LibJPEG": "https://libjpeg.sourceforge.io/",
        "OpenAMP": "https://www.openampproject.org/",
        "STM32_USB_Device_Library": "https://github.com/STMicroelectronics/STM32CubeH7",
        "STM32_USB_Host_Library": "https://github.com/STMicroelectronics/STM32CubeH7",
        "TouchGFX": "https://touchgfx.com/",
        "STemWin": "https://www.st.com/en/embedded-software/stemwin.html",
        "STM32_Audio": "https://www.st.com/en/embedded-software/stm32-audio-software.html",
        "STM32H7xx_HAL_Driver": "https://github.com/STMicroelectronics/STM32CubeH7",
        "CMSIS-RTOS": "https://www.keil.com/pack/doc/CMSIS/RTOS/",
    }

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
            background=[("selected", "#fff7d6")],
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
            foreground=self.TEXT_COLOR,
        )
        style.map(
            "TButton",
            background=[("active", "#e0c54f")],
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

        accent_bar = tk.Frame(self.sidebar, bg=self.ACCENT_COLOR, width=2)
        accent_bar.pack(fill="y", side="left")

        shortcuts = tk.Frame(self.sidebar, bg=self.SIDEBAR_COLOR)
        shortcuts.pack(fill="both", expand=True)

        self.sidebar_buttons = {}
        buttons = [
            ("📄", "sbom", lambda: self._show_view("sbom")),
            ("☰", "about", lambda: self._show_view("about")),
            ("🛡️", "libraries", lambda: self._show_view("libraries")),
        ]

        for icon, key, command in buttons:
            btn = tk.Button(
                shortcuts,
                text=icon,
                font=("Segoe UI Emoji", 16),
                fg=self.TEXT_COLOR,
                bg=self.SIDEBAR_COLOR,
                activebackground=self.PANEL_COLOR,
                activeforeground=self.ACCENT_COLOR,
                relief="flat",
                bd=0,
                highlightthickness=0,
                cursor="hand2",
                pady=10,
                command=command,
            )
            btn.pack(pady=6)
            self.sidebar_buttons[key] = btn

    def _build_layout(self) -> None:
        main_container = tk.Frame(self.root, bg=self.BG_COLOR)
        main_container.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(main_container, bg=self.SIDEBAR_COLOR, width=76)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        self._build_sidebar()

        self.content_container = tk.Frame(main_container, bg=self.BG_COLOR)
        self.content_container.pack(side="left", fill="both", expand=True)

        self.views = {}
        self._build_sbom_view()
        self._build_about_view()
        self._build_libraries_view()

        self._show_view("sbom")

    def _build_sbom_view(self) -> None:
        sbom_view = tk.Frame(self.content_container, bg=self.BG_COLOR)
        self.views["sbom"] = sbom_view

        header = tk.Frame(sbom_view, bg=self.BG_COLOR)
        header.pack(fill="x", pady=(16, 8), padx=16)

        title = tk.Label(
            header,
            text="Logika SBOM Checker",
            fg=self.ACCENT_COLOR,
            bg=self.BG_COLOR,
            font=("Inter", 18, "bold"),
        )
        title.pack(anchor="w")

        subtitle = tk.Label(
            header,
            text="View and inspect the loaded SBOM (.json or .spdx)",
            fg=self.MUTED_TEXT_COLOR,
            bg=self.BG_COLOR,
            font=("Inter", 11),
        )
        subtitle.pack(anchor="w")

        controls = tk.Frame(sbom_view, bg=self.BG_COLOR)
        controls.pack(fill="x", padx=16, pady=(0, 12))

        left = tk.Frame(controls, bg=self.BG_COLOR)
        left.pack(side="left", padx=(4, 0), pady=8)

        select_btn = ttk.Button(
            left,
            text="Generate report",
            command=self._on_select_file,
            style="TButton",
        )
        select_btn.pack(side="left")

        clear_btn = ttk.Button(
            left,
            text="Delete selection",
            command=self._clear_selection,
            style="TButton",
        )
        clear_btn.pack(side="left", padx=(8, 0))

        self.selected_file_label = tk.Label(
            left,
            text="No file selected",
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

        self.body = tk.PanedWindow(
            sbom_view,
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

    def _build_about_view(self) -> None:
        about_view = tk.Frame(self.content_container, bg=self.BG_COLOR)
        self.views["about"] = about_view

        header = tk.Frame(about_view, bg=self.BG_COLOR)
        header.pack(fill="x", pady=(16, 8), padx=16)

        title = tk.Label(
            header,
            text="Logika SBOM Checker",
            fg=self.ACCENT_COLOR,
            bg=self.BG_COLOR,
            font=("Inter", 18, "bold"),
        )
        title.pack(anchor="w")

        subtitle = tk.Label(
            header,
            text="A product by Logika Control S.r.l.",
            fg=self.MUTED_TEXT_COLOR,
            bg=self.BG_COLOR,
            font=("Inter", 11),
        )
        subtitle.pack(anchor="w")

        content = tk.Frame(about_view, bg=self.BG_COLOR)
        content.pack(fill="both", expand=True, padx=16, pady=16)

        description = (
            "Logika SBOM Checker streamlines the validation of software bills of materials "
            "for STM32 firmware. Load an SBOM, review library versions, and check whether "
            "newer security updates are available."
        )

        tk.Label(
            content,
            text="Application description",
            bg=self.BG_COLOR,
            fg=self.TEXT_COLOR,
            font=("Inter", 14, "bold"),
        ).pack(anchor="w", pady=(0, 12))

        tk.Label(
            content,
            text=description,
            wraplength=760,
            justify="left",
            bg=self.BG_COLOR,
            fg=self.TEXT_COLOR,
            font=("Inter", 12),
        ).pack(anchor="w")

    def _build_libraries_view(self) -> None:
        libraries_view = tk.Frame(self.content_container, bg=self.BG_COLOR)
        self.views["libraries"] = libraries_view

        header = tk.Frame(libraries_view, bg=self.BG_COLOR)
        header.pack(fill="x", pady=(16, 8), padx=16)

        title = tk.Label(
            header,
            text="Supported libraries",
            fg=self.ACCENT_COLOR,
            bg=self.BG_COLOR,
            font=("Inter", 18, "bold"),
        )
        title.pack(anchor="w")

        tk.Label(
            header,
            text="Versions based on STM32CubeH7 releases (STM32CubeH7 GitHub)",
            fg=self.MUTED_TEXT_COLOR,
            bg=self.BG_COLOR,
            font=("Inter", 11),
        ).pack(anchor="w")

        disclaimer = tk.Label(
            libraries_view,
            text=(
                "Library versions reference the STMicroelectronics STM32CubeH7 repository: "
                "https://github.com/STMicroelectronics/STM32CubeH7"
            ),
            fg=self.TEXT_COLOR,
            bg=self.BG_COLOR,
            font=("Inter", 11),
            wraplength=780,
            justify="left",
        )
        disclaimer.pack(fill="x", padx=16)

        container = tk.Frame(libraries_view, bg=self.BG_COLOR)
        container.pack(fill="both", expand=True, padx=16, pady=12)

        canvas = tk.Canvas(
            container, bg=self.BG_COLOR, highlightthickness=0, borderwidth=0
        )
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.library_list_frame = tk.Frame(canvas, bg=self.BG_COLOR)

        self.library_list_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )

        canvas.create_window((0, 0), window=self.library_list_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.library_canvas = canvas
        self._populate_library_view()
        self._bind_mousewheel(canvas)

    def _show_view(self, key: str) -> None:
        for name, frame in self.views.items():
            if name == key:
                frame.pack(fill="both", expand=True)
            else:
                frame.pack_forget()

        for name, btn in getattr(self, "sidebar_buttons", {}).items():
            if name == key:
                btn.configure(fg=self.ACCENT_COLOR)
            else:
                btn.configure(fg=self.MUTED_TEXT_COLOR)

        if key == "libraries":
            self._populate_library_view()

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
            "up-to-date", background="#f0f6e5", foreground=self.TEXT_COLOR
        )
        self.tree.tag_configure(
            "unknown", background="#fff7d6", foreground=self.ACCENT_COLOR
        )

        self._bind_mousewheel(self.tree)

    def _build_notes_panel(self) -> None:
        notes_frame = tk.LabelFrame(
            self.body,
            text="Security notes",
            bg=self.PANEL_COLOR,
            fg=self.TEXT_COLOR,
            font=("Inter", 12, "bold"),
        )
        self.body.add(notes_frame, minsize=200, stretch="always")

        self.notes_box = tk.Text(
            notes_frame,  # fix: previously notes_container
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

        self._bind_mousewheel(self.notes_box)

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

    def _bind_mousewheel(self, widget: tk.Widget) -> None:
        """Enable mouse wheel scrolling for a given widget across platforms."""

        def _unbound() -> None:
            for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                self.root.unbind_all(sequence)

        def _bind_to(event: tk.Event) -> None:  # type: ignore[override]
            _unbound()
            self.root.bind_all("<MouseWheel>", lambda e: self._on_mousewheel(widget, e))
            self.root.bind_all("<Button-4>", lambda e: self._on_mousewheel(widget, e))
            self.root.bind_all("<Button-5>", lambda e: self._on_mousewheel(widget, e))

        widget.bind("<Enter>", _bind_to)
        widget.bind("<Leave>", lambda _evt: _unbound())

    def _on_mousewheel(self, widget: tk.Widget, event: tk.Event) -> None:  # type: ignore[override]
        if not hasattr(widget, "yview_scroll"):
            return

        if getattr(event, "num", None) == 4:
            direction = -1
        elif getattr(event, "num", None) == 5:
            direction = 1
        else:
            direction = -1 if event.delta > 0 else 1

        widget.yview_scroll(direction, "units")

    def _on_select_file(self) -> None:
        filepath = filedialog.askopenfilename(
            title="Select an SBOM file",
            filetypes=[("SBOM files", "*.json *.spdx"), ("All files", "*.*")],
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
                "Error", f"Unable to read the SBOM file:\n{exc}"
            )
            return

        self.selected_file_label.config(text=path.name, fg=self.TEXT_COLOR)
        self._populate_table(data)
        self._populate_notes(data)
        self._update_summary(data)

    def _clear_selection(self) -> None:
        self.selected_file_label.config(text="No file selected", fg=self.MUTED_TEXT_COLOR)
        self.tree.delete(*self.tree.get_children())
        self.notes_box.config(state="normal")
        self.notes_box.delete("1.0", "end")
        self.notes_box.config(state="disabled")
        self.update_label.config(text="", fg=self.TEXT_COLOR)

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
                "No security updates detected in later versions.",
            )
        else:
            if cve_sections:
                self.notes_box.insert("end", "CVE list\n", ("section",))
                for lib in cve_sections:
                    self.notes_box.insert("end", f"{lib['name']}\n", ("title",))
                    for rel in lib.get("cve_notes", []):
                        cve = (rel.get("cve") or "").strip()
                        if not cve:
                            continue
                        version = rel.get("version", "")
                        date = rel.get("release_date") or "date n/a"
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
                self.notes_box.insert("end", "Security notes\n", ("section",))
                for lib in notes_to_print:
                    self.notes_box.insert("end", f"{lib['name']}\n", ("title",))
                    for rel in lib["security_notes"]:
                        version = rel.get("version", "")
                        date = rel.get("release_date") or "date n/a"
                        notes = rel.get("release_notes") or "Release notes not available."
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
            text = f"Libraries to update: {count_needs_update}"
            color = self.ALERT_COLOR
        else:
            text = "Tutte le librerie sono aggiornate"
            color = self.TEXT_COLOR
        self.update_label.config(text=text, fg=color)

    def _populate_library_view(self) -> None:
        for widget in self.library_list_frame.winfo_children():
            widget.destroy()

        names = sorted(get_library_names(), key=str.lower)
        if not names:
            tk.Label(
                self.library_list_frame,
                text="No libraries found in the database.",
                bg=self.BG_COLOR,
                fg=self.TEXT_COLOR,
                font=("Inter", 12),
            ).pack(anchor="w", pady=8)
            return

        for name in names:
            releases = list(reversed(get_releases_for_library(name)))
            section = tk.Frame(self.library_list_frame, bg=self.BG_COLOR)
            section.pack(fill="x", pady=(0, 12))

            header = tk.Frame(section, bg=self.BG_COLOR)
            header.pack(fill="x")

            tk.Label(
                header,
                text=name,
                bg=self.BG_COLOR,
                fg=self.TEXT_COLOR,
                font=("Inter", 13, "bold"),
            ).pack(side="left")

            link = self.LIBRARY_LINKS.get(name)
            if link:
                link_label = tk.Label(
                    header,
                    text=link,
                    bg=self.BG_COLOR,
                    fg=self.ACCENT_COLOR,
                    font=("Inter", 10, "underline"),
                    cursor="hand2",
                    wraplength=400,
                    justify="left",
                )
                link_label.pack(side="left", padx=(8, 0))
                link_label.bind("<Button-1>", lambda _evt, url=link: webbrowser.open(url))

            versions_frame = tk.Frame(section, bg=self.BG_COLOR)
            versions_frame.pack(fill="x", padx=(8, 0), pady=(4, 0))

            if releases:
                for rel in releases:
                    version = rel.get("version") or "n/a"
                    date = rel.get("release_date") or "date n/a"
                    tk.Label(
                        versions_frame,
                        text=f"- {version} ({date})",
                        bg=self.BG_COLOR,
                        fg=self.MUTED_TEXT_COLOR,
                        font=("Inter", 11),
                        justify="left",
                        anchor="w",
                    ).pack(anchor="w")
            else:
                tk.Label(
                    versions_frame,
                    text="No versions available",
                    bg=self.BG_COLOR,
                    fg=self.MUTED_TEXT_COLOR,
                    font=("Inter", 11),
                ).pack(anchor="w")

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    app = SBOMCheckerGUI()
    app.run()


if __name__ == "__main__":
    main()
