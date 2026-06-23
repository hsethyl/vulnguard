"""PyInstaller entry point for the VulnGuard GUI.

A top-level script (not a package module) so PyInstaller can use it as the
build entry; it simply launches the package's GUI.
"""

from vulnguard.gui import main

if __name__ == "__main__":
    raise SystemExit(main())
