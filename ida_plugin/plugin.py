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
        show_resolver_dialog()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return HashResolverPlugin()
