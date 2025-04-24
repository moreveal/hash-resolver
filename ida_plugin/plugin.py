import ida_kernwin
import idaapi

from .ui_form import register_context_action, show_resolver_dialog


class HashResolverPlugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = "Resolve hashes using emulated function calls"
	help = "Resolve hash → string using API call emulation"
	wanted_name = "Hash Resolver"
	wanted_hotkey = ""

	def init(self):
		register_context_action()
		return idaapi.PLUGIN_OK

	def run(self, arg):
		func = idaapi.get_func(ida_kernwin.get_screen_ea())
		if not func:
			ida_kernwin.warning("Cursor is not on a function")
			return
		start = func.start_ea
		end = func.end_ea
		size = end - start
		code = idaapi.get_bytes(start, size)
		show_resolver_dialog(func_name=idaapi.get_func_name(start), func_bytes=code, func_address=start)


	def term(self):
		pass


def PLUGIN_ENTRY():
	return HashResolverPlugin()
