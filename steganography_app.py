import ttkbootstrap as tb
from gui import SteganographyApp

def main():
    root = tb.Window(themename="superhero")
    app = SteganographyApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
