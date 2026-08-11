#main file

from getpass import getpass
import curses
from cryptography import HMAC
from __asciistuff import smollertopasciiart, titleasciiart, spinner
from time import sleep, time

def main(stdscr:curses.window):
    curses.curs_set(0) # hide cursor
    curses.start_color()
    stdscr.clear()
    stdscr.border()
    stdscr.timeout(100)
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)

    x_margin = 4
    y_margin = 2
    y_max, x_max = stdscr.getmaxyx()
    if x_max < 50 or y_max < 20:
        raise Exception("Terminal window is too small!!! please resize")
    win = stdscr.subwin((y_max - (y_margin*4)), (x_max - (x_margin*4)), y_margin, x_margin)
    stdscr.attrset(curses.color_pair(1))

    #title:
    for i, line in enumerate(smollertopasciiart.splitlines()):
        win.addstr(y_margin+i, x_margin, line, curses.color_pair(1))
    for i, line in enumerate(titleasciiart.splitlines()):
        win.addstr(y_margin+3+i, x_margin+40, line, curses.color_pair(1))
    win.addstr(y_margin+23, x_margin+4, "Press any key to start SmolTOP!")
    win.refresh()

    frame=0
    while True:
        if frame > 999:
            frame=0
        win.addstr(y_margin+23, x_margin+35, spinner[frame % len(spinner)])
        win.addstr(y_margin+23, x_margin+2, spinner[frame % len(spinner)])
        win.refresh()
        frame+=1
        key = win.getch()
        if key != -1:
            break
        sleep(0.05)

    #menus:

    

if __name__=="__main__":
    curses.wrapper(main)