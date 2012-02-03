# stopmsg.py
from Tkinter import *

class Application(Frame):
    def say_hi(self):
        print "PGO-gen is not finished!"

    def createWidgets(self):
        self.QUIT = Button(self)
        self.QUIT["text"] = "PGO-gen finished"
        self.QUIT["fg"]   = "red"
        self.QUIT["command"] =  self.quit

        self.QUIT.pack({"side": "left"})

        self.hi_there = Button(self)
        self.hi_there["text"] = "PGO-gen is not finished",
        self.hi_there["command"] = self.say_hi

        self.hi_there.pack({"side": "left"})

    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.pack()
        self.createWidgets()

root = Tk()
app = Application(master=root)
app.mainloop()
root.destroy()