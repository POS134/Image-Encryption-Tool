Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "D:\Master's Thesis\SecureImageGuard"
WshShell.Run "pythonw app.py", 0, False
