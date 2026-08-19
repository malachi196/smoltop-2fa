# Copyright (C) 2026 @malachi196
#
# This file is part of SmolTOP
#
# SmolTOP is a Time-based One Time Pass (TOTP) 2 Factor Authentication (2FA)
# tool that is designed to be very small (smol), and relatively lightweight. This 
# helps make it portable and convenient at a moment's notice, without using too
# many system resources.
#
# SmolTOP is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# SmolTOP is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

#main file

from getpass import getpass
import curses
from cryptography import HMAC
from __asciistuff import smollertopasciiart, titleasciiart, spinner
from time import sleep, time
from pathlib import Path
import json
import logging
import sys
import traceback

THISPATH = Path(__file__).resolve().parent

logging.basicConfig(
    filename=f"{THISPATH}/crash.log",
    encoding="utf-8",
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

def main(stdscr:curses.window):
    curses.curs_set(0) # hide cursor
    curses.start_color()
    stdscr.clear()
    stdscr.timeout(100)
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1) #standard color
    curses.init_pair(2, curses.COLOR_CYAN, -1) #special text color
    curses.init_pair(3, curses.COLOR_RED, -1)  #error color

    x_margin = 4
    y_margin = 2
    y_max, x_max = stdscr.getmaxyx()
    if x_max < 103 or y_max < 24:
        raise Exception("Terminal window is too small!!! please resize")
    win = stdscr.subwin((y_max - (y_margin*4)), (x_max - (x_margin*4)), y_margin, x_margin)

    #title:
    for i, line in enumerate(smollertopasciiart.splitlines()):
        win.addstr(y_margin+i, x_margin, line, curses.color_pair(1))
    for i, line in enumerate(titleasciiart.splitlines()):
        win.addstr(y_margin+3+i, x_margin+40, line, curses.color_pair(1))
    win.addstr(y_margin+23, x_margin+4, "Press any key to start SmolTOP!", curses.color_pair(2))
    win.refresh()

    frame=0
    stdscr.border()
    while True:
        if frame > 999:
            frame=0
        win.addstr(y_margin+23, x_margin+36, spinner[frame % len(spinner)], curses.color_pair(2))
        win.addstr(y_margin+23, x_margin+2, spinner[frame % len(spinner)], curses.color_pair(2))
        win.refresh()
        frame+=1
        key = win.getch()
        if key != -1:
            break
        sleep(0.05)
    win.nodelay(False)
    curses.cbreak(True) #get keys instantly without waiting for enter
    win.timeout(-1)
    win.clear()
    #checking and setting up
    if not Path(f"{THISPATH}/data").is_dir():
        Path(f"{THISPATH}/data").mkdir()
    if not Path(f"{THISPATH}/data/smltpksndpss.json").is_file():
        Path(f"{THISPATH}./data/smltpksndpss.json").touch()
        with open(f"{THISPATH}./data/smltpksndpss.json", "w") as f:
            f.write(r"{ }")
    datafile = __loaddatafile(win)
    if "meinkennwort" not in datafile:
        win.clear()
        stdscr.border()
        newpass = ""
        while True:
            win.addstr("No master password detected\n\n", curses.color_pair(1))
            win.addstr("New Password:\n", curses.color_pair(1))
            win.addstr("> ", curses.color_pair(1))
            newpass = __readpasswd(win)
            win.addstr(f"\nConfirm password:\n", curses.color_pair(1))
            win.addstr("> ", curses.color_pair(1))
            confpass = __readpasswd(win)
            if newpass == confpass:
                break
            else:
                curses.curs_set(0)
                win.addstr("\nPasswords don't match!\n", curses.color_pair(3))
                _ = win.getch()
                win.clear()
        try:
            datafile["meinkennwort"] = newpass
            __dumptodatafile(win, datafile) #TEMP (for testing) password will be encrypted in final
        except Exception:
            win.addstr(f"\nFailed to set master password!\n", curses.color_pair(3))
            __crashhandler(win)
        win.addstr(f"\n\nMaster Password set successfully!\n", curses.color_pair(2))

        win.refresh()
        curses.flushinp()
        _ = win.getch()
    else:
        win.addstr("Password was found\n", curses.color_pair(1)) #TEMP (for testing). Replace with password checking option


    _ = win.getch()
    
def __readpasswd(win:curses.window):
    curses.noecho()
    newpass = ""
    curses.curs_set(True)
    while True:
        l = win.getch()
        if l in (10, 13, curses.KEY_ENTER):
            if len(newpass) > 0:
                break
            else:
                continue
        if l in (curses.KEY_BACKSPACE, 8, 127):
            _y, _x = win.getyx()
            if _x > 2:
                win.addstr("\b \b")
                newpass = newpass[:-1]
            win.refresh()
            continue
        newpass+=chr(l)
        win.addstr("*", curses.color_pair(2))
    return newpass

def __loaddatafile(win:curses.window):
    try:
        with open(f"{THISPATH}/data/smltpksndpss.json", "r") as f:
            datafile = json.load(f)
        return datafile
    except json.decoder.JSONDecodeError as e:
        try:
            with open(f"{THISPATH}/data/smltpksndpss.json", "r+") as f:
                if f.read().strip("\n") == "":
                    f.write(r"{ }")
        except json.decoder.JSONDecodeError:
            win.addstr("\nDatafile format was not readable!\n", curses.color_pair(3))
            __crashhandler(win)
    except Exception as e:
        win.addstr("\nError while trying to load datafile!\n", curses.color_pair(3))
        __crashhandler(win)

def __dumptodatafile(win, data):
    try:
        with open(f"{THISPATH}/data/smltpksndpss.json", "w") as f:
            json.dump(data, f)
    except json.decoder.JSONDecodeError as e:
        win.addstr("\nDatafile format was not readable!\n", curses.color_pair(3))
        __crashhandler(win)
    except Exception as e:
        win.addstr("\nError while trying to dump to datafile!\n", curses.color_pair(3))
        __crashhandler(win)

def __crashhandler(win:curses.window):
    win.addstr("traceback saved to \"crash.log\"", curses.color_pair(3))
    e = traceback.format_exc()
    logging.error(e)
    curses.curs_set(False)
    win.timeout(-1)
    _ = win.getch()
    sys.exit(1)

if __name__=="__main__":
    curses.wrapper(main)