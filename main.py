import os, sys
sys.stdout = open(os.devnull, "w")
sys.stderr = open(os.devnull, "w")


from gui.mainGUI import run_gui
if __name__ == "__main__":
    run_gui()
