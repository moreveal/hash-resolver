import ida_kernwin
import ida_funcs
import ida_bytes

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QLineEdit,
    QPushButton, QFileDialog, QMessageBox,
    QFormLayout
)

from PyQt5.QtCore import QSettings
SETTINGS_ORG = "hashres"
SETTINGS_APP = "HashResolver"
SETTINGS_PATH_KEY = "symbols_path"
SETTINGS_PATTERN_KEY = "last_pattern"

import json
from pathlib import Path

this_dir = Path(__file__).parent
signatures_dir = this_dir / "signatures"

from hash_resolver.pattern import Pattern
from hash_resolver.core import resolve_hash
from hash_resolver.utils import parse_hex_fields

class ResolverActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        ea = ctx.cur_ea
        func = ida_funcs.get_func(ea)
        if not func:
            ida_kernwin.msg("No function at EA\n")
            return 0

        start = func.start_ea
        end = func.end_ea
        size = end - start
        code = ida_bytes.get_bytes(start, size)

        from .ui_form import show_resolver_dialog
        show_resolver_dialog(func_name=ida_funcs.get_func_name(ea), func_bytes=code)

        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB


ACTION_NAME = "hashres:resolve_context"
ACTION_LABEL = "Resolve hash for this function"

class ContextMenuHook(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle):
        if ida_kernwin.get_widget_type(widget) in [
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_PSEUDOCODE,
        ]:
            ida_kernwin.attach_action_to_popup(
                widget,
                popup_handle,
                ACTION_NAME,
                None,
            )


def register_context_action():
    desc = ida_kernwin.action_desc_t(
        ACTION_NAME,
        ACTION_LABEL,
        ResolverActionHandler(),
        None,
        "Resolve hash using this function",
    )
    ida_kernwin.register_action(desc)

    # hook UI
    global _ctx_hook
    _ctx_hook = ContextMenuHook()
    _ctx_hook.hook()


def show_resolver_dialog(func_name=None, func_bytes=None):
    class ResolverDialog(QDialog):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Hash Resolver")
            self.setMinimumWidth(600)

            layout = QVBoxLayout()
            
            self.settings = QSettings(SETTINGS_ORG, SETTINGS_APP)

            # --- Pattern dropdown ---
            self.pattern_combo = QComboBox()
            self.pattern_paths = []
            for f in signatures_dir.glob("*.json"):
                self.pattern_combo.addItem(f.name)
                self.pattern_paths.append(f)
                
            last_pattern = self.settings.value(SETTINGS_PATTERN_KEY, "")
            if last_pattern:
                index = self.pattern_combo.findText(last_pattern)
                if index != -1:
                    self.pattern_combo.setCurrentIndex(index)


            layout.addWidget(QLabel("Pattern:"))
            layout.addWidget(self.pattern_combo)

            # --- Hash field ---
            self.hash_input = QLineEdit()
            self.hash_input.setPlaceholderText("e.g. 0x53B2070F")
            self.hash_input.textChanged.connect(self.on_hash_changed)
            layout.addWidget(QLabel("Hash:"))
            layout.addWidget(self.hash_input)

            # --- Symbols path ---
            symbols_layout = QHBoxLayout()

            self.symbols_input = QLineEdit()
            self.symbols_input.setPlaceholderText("e.g. C:/symbols/kernel32.txt")
            last_path = self.settings.value(SETTINGS_PATH_KEY, "")
            if last_path:
                self.symbols_input.setText(last_path)

            browse_btn = QPushButton("...")
            browse_btn.clicked.connect(self.browse_symbols)

            symbols_layout.addWidget(self.symbols_input)
            symbols_layout.addWidget(browse_btn)

            def browse_symbols():
                path, _ = QFileDialog.getOpenFileName(self, "Select symbols file", ".", "Text files (*.txt)")
                if path:
                    self.symbols_input.setText(path)

            browse_btn.clicked.connect(browse_symbols)

            sym_row = QHBoxLayout()
            sym_row.addWidget(self.symbols_input)
            sym_row.addWidget(browse_btn)

            layout.addWidget(QLabel("Symbols list:"))
            layout.addLayout(sym_row)
            
            # --- Argument inputs ---
            self.arg_inputs = {}
            self.arg_layout = QFormLayout()
            layout.addLayout(self.arg_layout)
            # Connect pattern change
            self.pattern_combo.currentIndexChanged.connect(self.update_arg_inputs)
            self.update_arg_inputs() # trigger first load

            # --- Buttons ---
            btn_row = QHBoxLayout()
            ok_btn = QPushButton("OK")
            cancel_btn = QPushButton("Cancel")

            ok_btn.clicked.connect(self.handle_ok)
            cancel_btn.clicked.connect(self.reject)

            btn_row.addWidget(ok_btn)
            btn_row.addWidget(cancel_btn)
            layout.addLayout(btn_row)

            self.setLayout(layout)
            
        def update_arg_inputs(self):
            # Clear previous
            for i in reversed(range(self.arg_layout.count())):
                self.arg_layout.itemAt(i).widget().setParent(None)
            self.arg_inputs.clear()

            # Load selected pattern
            idx = self.pattern_combo.currentIndex()
            try:
                data = json.loads(self.pattern_paths[idx].read_text())
                args = data.get("args", [])
            except Exception as e:
                QMessageBox.critical(self, "Pattern Load Failed", f"Failed to parse pattern: {e}")
                return

            # Render fields
            for arg in args:
                if arg.get("resolve_input"):
                    continue

                name = arg["name"]
                typ = arg["type"]
                le = QLineEdit()
                if "default" in arg:
                    le.setText(str(arg["default"]))
                self.arg_inputs[name] = le
                self.arg_layout.addRow(f"{name} ({typ})", le)

            
        def browse_symbols(self):
            path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Symbols File",
                "",
                "Text Files (*.txt);;All Files (*)"
            )
            if path:
                self.symbols_input.setText(path)
                
        def on_hash_changed(self, text):
            if text and not text.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in text):
                self.hash_input.setText("0x" + text)


        def handle_ok(self):
            # Load saved
            symbols_path = self.symbols_input.text()
            self.settings.setValue(SETTINGS_PATH_KEY, symbols_path)

            current_pattern = self.pattern_combo.currentText()
            self.settings.setValue(SETTINGS_PATTERN_KEY, current_pattern)

            # ----------

            # Parse hash
            try:
                raw = self.hash_input.text().strip()
                h = int(raw, 16) if raw.startswith("0x") else int(raw)
            except Exception:
                QMessageBox.warning(self, "Invalid input", "Could not parse hash")
                return

            # Load pattern
            idx = self.pattern_combo.currentIndex()
            pattern_path = self.pattern_paths[idx]
            try:
                data = json.loads(pattern_path.read_text())
                data["emu"] = parse_hex_fields(data["emu"])
                pattern = Pattern(data)
            except Exception as e:
                QMessageBox.critical(self, "Pattern Error", f"Failed to load pattern: {e}")
                return

            # Load symbols
            try:
                syms = Path(self.symbols_input.text()).read_text(encoding="utf-8").splitlines()
            except Exception as e:
                QMessageBox.critical(self, "Symbols Error", f"Failed to load symbols: {e}")
                return

            # Resolve
            try:
                args = {
                    name: field.text().strip()
                    for name, field in self.arg_inputs.items()
                }
                                
                result = resolve_hash(pattern, func_bytes, h, candidates=syms, arguments=args)
                if result:
                    QMessageBox.information(self, "Resolved", f"0x{h:08X} → {', '.join(result)}")
                else:
                    QMessageBox.information(self, "No Match", f"No symbol matched for 0x{h:08X}")
            except Exception as e:
                QMessageBox.critical(self, "Emulation Failed", f"{e}")

    ResolverDialog().exec_()
