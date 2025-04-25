import idaapi
import ida_kernwin
import ida_funcs
import ida_bytes
import ida_enum
import idc

from PyQt5.QtWidgets import (
	QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QLineEdit,
	QPushButton, QFileDialog, QMessageBox, QFormLayout, QTabWidget, QProgressBar,
)
from PyQt5.QtCore import QSettings, QThread, pyqtSignal
from pathlib import Path
import json

from hash_resolver.core import bulk_generate_hashes
from hash_resolver.execution.emulated import EmulatedContext
from hash_resolver.execution.runtime import RuntimeContext
from hash_resolver.execution.runtime_launcher import launch_runtime_process, kill_runtime_process
from hash_resolver.emulator import Emulator

from hash_resolver.loader import load_pattern

SETTINGS_ORG = "hashres"
SETTINGS_APP = "HashResolver"
SETTINGS_PATH_KEY = "symbols_path"
SETTINGS_PATTERN_KEY = "last_pattern"

signatures_dir = Path(__file__).parent / "signatures"

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
		show_resolver_dialog(func_name=ida_funcs.get_func_name(ea), func_bytes=code, func_address=start)

		return 1

	def update(self, ctx):
		return ida_kernwin.AST_ENABLE_FOR_IDB

ACTION_NAME = "hashres:resolve_context"
ACTION_LABEL = "Hash Resolver: Generate hashmap"

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

class HashWorker(QThread):
	progress = pyqtSignal(int)      # Signal: how many steps to advance
	done = pyqtSignal(dict)         # Signal: completed with result

	def __init__(self, ctx, pattern, func, symbols, args):
		super().__init__()
		self.ctx = ctx
		self.pattern = pattern
		self.func = func
		self.symbols = symbols
		self.args = args

	def run(self):
		def callback(_, __):
			self.progress.emit(1)

		try:
			result = bulk_generate_hashes(
				self.ctx,
				self.pattern,
				self.func,
				self.symbols,
				self.args,
				callback=callback
			)
		except Exception:
			result = {}
		finally:
			self.ctx.cleanup()

		self.done.emit(result)
  
def register_context_action():
	desc = ida_kernwin.action_desc_t(
		ACTION_NAME,
		ACTION_LABEL,
		ResolverActionHandler(),
		None,
		"Generate hashmap",
	)
	ida_kernwin.register_action(desc)

	# hook UI
	global _ctx_hook
	_ctx_hook = ContextMenuHook()
	_ctx_hook.hook()
 
def show_resolver_dialog(func_name=None, func_bytes=None, func_address=None):
	class ResolverDialog(QDialog):
		def __init__(self):
			super().__init__()
			self.setWindowTitle("Hash Resolver")
			self.setMinimumWidth(600)

			self.settings = QSettings(SETTINGS_ORG, SETTINGS_APP)
			layout = QVBoxLayout()

			self.tabs = QTabWidget()
			self.tabs.addTab(self.build_emu_tab(func_bytes), "Emulated")
			self.tabs.addTab(self.build_runtime_tab(func_address), "Runtime")

			layout.addWidget(self.tabs)
			self.setLayout(layout)

		def build_emu_tab(self, func_bytes):
			tab = QVBoxLayout()

			self.pattern_combo = QComboBox()
			self.pattern_paths = []
			for f in signatures_dir.glob("*.json"):
				self.pattern_combo.addItem(f.name)
				self.pattern_paths.append(f)
			tab.addWidget(QLabel("Signature:"))
			tab.addWidget(self.pattern_combo)

			# symbols
			self.symbols_input_emu = QLineEdit()
			self.symbols_input_emu.setPlaceholderText("Path to symbols.txt")
			btn_sym = QPushButton("...")
			btn_sym.clicked.connect(lambda: self.browse_file(self.symbols_input_emu))
			row = QHBoxLayout()
			row.addWidget(self.symbols_input_emu)
			row.addWidget(btn_sym)
			tab.addWidget(QLabel("Symbols list:"))
			tab.addLayout(row)

			# args
			self.arg_inputs_emu = {}
			self.arg_layout_emu = QFormLayout()
			tab.addLayout(self.arg_layout_emu)
			self.pattern_combo.currentIndexChanged.connect(self.update_args_emu)
			self.update_args_emu()

			# output
			self.enum_name_emu = QLineEdit()
			self.enum_name_emu.setPlaceholderText("Enum name (e.g., hashresolver_sym)")
			tab.addWidget(QLabel("Enum name:"))
			tab.addWidget(self.enum_name_emu)

			# progress + buttons
			self.progress_emu = QProgressBar()
			self.progress_emu.setVisible(False)
			tab.addWidget(self.progress_emu)

			btn = QPushButton("Run")
			btn.clicked.connect(lambda: self.run_bulk("emu", func_bytes))
	
			tab.addWidget(btn)

			widget = QDialog()
			widget.setLayout(tab)
			return widget

		def build_runtime_tab(self, func_address):
			tab = QVBoxLayout()

			self.pattern_combo_rt = QComboBox()
			self.pattern_paths_rt = []
			for f in signatures_dir.glob("*.json"):
				self.pattern_combo_rt.addItem(f.name)
				self.pattern_paths_rt.append(f)
			tab.addWidget(QLabel("Signature:"))
			tab.addWidget(self.pattern_combo_rt)

			self.exepath_input = QLineEdit()
			self.exepath_input.setPlaceholderText("Path to EXE")
			btn_exe = QPushButton("...")
			btn_exe.clicked.connect(lambda: self.browse_file(self.exepath_input))
			row_exe = QHBoxLayout()
			row_exe.addWidget(self.exepath_input)
			row_exe.addWidget(btn_exe)
			tab.addWidget(QLabel("Target EXE:"))
			tab.addLayout(row_exe)

			self.symbols_input_rt = QLineEdit()
			btn_sym = QPushButton("...")
			btn_sym.clicked.connect(lambda: self.browse_file(self.symbols_input_rt))
			row = QHBoxLayout()
			row.addWidget(self.symbols_input_rt)
			row.addWidget(btn_sym)
			tab.addWidget(QLabel("Symbols list:"))
			tab.addLayout(row)

			# auto rva from current func
			imagebase = idaapi.get_imagebase()
			rva = func_address - imagebase if func_address else 0
			self.rva_input = QLineEdit(str(hex(rva)))
			tab.addWidget(QLabel("Hasher RVA:"))
			tab.addWidget(self.rva_input)

			self.arg_inputs_rt = {}
			self.arg_layout_rt = QFormLayout()
			tab.addLayout(self.arg_layout_rt)
			self.pattern_combo_rt.currentIndexChanged.connect(self.update_args_rt)
			self.update_args_rt()

			self.enum_name_rt = QLineEdit()
			self.enum_name_rt.setPlaceholderText("Enum name (e.g., hashresolver_sym)")
			tab.addWidget(QLabel("Enum name:"))
			tab.addWidget(self.enum_name_rt)

			self.progress_rt = QProgressBar()
			self.progress_rt.setVisible(False)
			tab.addWidget(self.progress_rt)

			btn = QPushButton("Run")
			btn.clicked.connect(lambda: self.run_bulk("runtime"))
			tab.addWidget(btn)

			widget = QDialog()
			widget.setLayout(tab)
			return widget

		def update_args_emu(self):
			self.update_args(self.pattern_paths, self.pattern_combo, self.arg_inputs_emu, self.arg_layout_emu)

		def update_args_rt(self):
			self.update_args(self.pattern_paths_rt, self.pattern_combo_rt, self.arg_inputs_rt, self.arg_layout_rt)

		def update_args(self, pattern_paths, pattern_combo, inputs_dict, layout):
			for i in reversed(range(layout.count())):
				layout.itemAt(i).widget().setParent(None)
			inputs_dict.clear()
			idx = pattern_combo.currentIndex()
			data = json.loads(pattern_paths[idx].read_text())
			for arg in data.get("args", []):
				if arg.get("resolve_input"):
					continue
				le = QLineEdit()
				if "default" in arg:
					le.setText(str(arg["default"]))
				elif arg['type'].endswith('*'): # do not allow manual setting of pointers
					continue
				inputs_dict[arg["name"]] = le
				layout.addRow(f"{arg['name']} ({arg['type']})", le)

		def browse_file(self, lineedit, save=False):
			if save:
				path, _ = QFileDialog.getSaveFileName(self, "Select file", ".", "JSON (*.json)")
			else:
				path, _ = QFileDialog.getOpenFileName(self, "Select file", ".", "All Files (*)")
			if path:
				lineedit.setText(path)

		def run_bulk(self, mode, func_bytes=None):
			try:
				if mode == "emu":
					syms_path = self.symbols_input_emu.text()
					enum_name = self.enum_name_emu.text().strip()
					args = {k: v.text().strip() for k, v in self.arg_inputs_emu.items()}
					pattern = load_pattern(self.pattern_paths[self.pattern_combo.currentIndex()])
					ctx = EmulatedContext(Emulator(pattern.arch, pattern.emu))
					symbols = Path(syms_path).read_text().splitlines()
					bar = self.progress_emu
					func = func_bytes
				elif mode == "runtime":
					syms_path = self.symbols_input_rt.text()
					enum_name = self.enum_name_rt.text().strip()
					args = {k: v.text().strip() for k, v in self.arg_inputs_rt.items()}
					pattern = load_pattern(self.pattern_paths[self.pattern_combo_rt.currentIndex()])
					exe = self.exepath_input.text()
					rva = int(self.rva_input.text(), 0)
					process, func = launch_runtime_process(exe, rva)
					ctx = RuntimeContext(process, pattern.arch)
					symbols = Path(syms_path).read_text().splitlines()
					bar = self.progress_rt
				else:
					QMessageBox.warning(self, "Error", "Unknown mode")
					return

				self.ctx = ctx
			except Exception as e:
				QMessageBox.critical(self, "Error", f"Unknown exception: {e}")
				return

			# Find the enum
			enum_id = idc.get_enum(enum_name)
			if enum_id != idc.BADADDR:
				resp = QMessageBox.question(
					self,
					"Enum exists",
					f"Enum '{enum_name}' already exists. Overwrite?",
					QMessageBox.Yes | QMessageBox.No,
					QMessageBox.No
				)
				if resp == QMessageBox.No:
					return
			else:
				enum_id = idc.add_enum(-1, enum_name, 0)
				if enum_id == idc.BADADDR:
					QMessageBox.critical(self, "Error", f"Failed to create enum: {enum_name}")
					return
			self.enum_id = enum_id

			self.thread = HashWorker(ctx, pattern, func, symbols, args)
			self.thread.progress.connect(lambda step: bar.setValue(bar.value() + step))
			self.thread.done.connect(lambda result: self.on_bulk_done(result, enum_name, mode))
			bar.setRange(0, len(symbols))
			bar.setValue(0)
			bar.setVisible(True)

			self.thread.start()
		
		def on_bulk_done(self, results: dict[str, int], enum_name: str, mode: str):
			added = 0
			for value, name in results.items():
				clean_name = f"h{name.capitalize()}"
				val = int(value, 16)
				result = ida_enum.add_enum_member(self.enum_id, clean_name, val, ida_enum.DEFMASK)
				if result == 0:
					added += 1
				else:
					print(f"[!] Failed to add {clean_name} = {value}")

			QMessageBox.information(self, "Done", f"Enum '{enum_name}' updated with {added} values.")

			self.ctx.cleanup()
			if mode == "runtime":
				kill_runtime_process(self.ctx.hProcess)

			self.progress_emu.setValue(0)
			self.progress_emu.setVisible(False)

			self.progress_rt.setValue(0)
			self.progress_rt.setVisible(False)
			

	ResolverDialog().exec_()
