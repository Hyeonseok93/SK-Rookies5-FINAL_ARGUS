import re

filepath = 'backend/diagnosis/modules/4-5/scanner.py'
with open(filepath, 'r', encoding='utf-8') as f:
    code = f.read()

# We only want to replace except Exception: pass inside functions that have _log defined.
# It's safer to just replace all `except Exception: pass` and `except Exception:\n                pass`
# with `except Exception as e: _log(f"    [Error] Exception: {e}")`.
# The only place without `_log` is around _read_api_tree and normalize_response_text.
# Those might throw NameError for `_log`, but actually let's just do a regex replace.
# Wait, for safety, I'll only replace the ones matching the indentations I know are inside functions with _log.

code = re.sub(
    r'(\s+)except Exception:\s+pass',
    r'\1except Exception as e:\n\1    try: _log(f"    [Error] Exception: {e}")\n\1    except NameError: pass',
    code
)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(code)
print("Done")
