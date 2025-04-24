from enum import Enum

def parse_hex_fields(emu: dict) -> dict:
    out = {}
    for k, v in emu.items():
        if isinstance(v, str) and v.startswith("0x"):
            out[k] = int(v, 16)
        else:
            out[k] = v
    return out

def build_arg_inputs(pattern, arguments=None, resolve=None):
    """
    Generates a list of argument values based on pattern and input data.

    :param pattern: pattern.args
    :param symbol: string to be substituted into resolve_input
    :param arguments: dictionary of manually defined arguments
    :param resolve: value for <resolve_input> item
    :return: list of values for arguments
    """
    arg_inputs = []

    for i, arg in enumerate(pattern.args):
        name = arg["name"]
        arg_type = arg["type"]

        if arguments and name in arguments:
            val = arguments[name]
        elif arg.get("resolve_input", False) and resolve is not None:
            val = resolve
        elif "default" in arg:
            val = arg["default"]
        elif arg_type.endswith("*"):
            # pointers will be allocated by self
            val = None
        else:
            raise ValueError(f"Missing argument: {name}")

        arg_inputs.append(val)

    return arg_inputs

