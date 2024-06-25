import tkinter as tk
from port_scanner import PortScannerApp

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
