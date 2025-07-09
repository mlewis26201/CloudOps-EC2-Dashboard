# PyQt-based GUI for EarlyResolution AWS EC2 Toolbox

This is the entry point for the GUI version. It will provide a windowed interface for listing, starting/stopping, and managing EC2 instances, as well as running SSM commands.

To run:

```sh
python gui_main.py
```

Requirements:
- PyQt5
- boto3
- rich (for possible logging)
- click, questionary (for CLI fallback)

You can install PyQt5 with:
```sh
pip install PyQt5
```

---

This is a work in progress. See `gui/gui_main.py` for the main application.
