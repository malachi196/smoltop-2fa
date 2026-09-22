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
from smoltop.cryptography import HMAC, AES128, PBKDF2, _DEFAULTPBKDF2COUNT, TOTP
from smoltop.__asciistuff import smollertopasciiart, titleasciiart, spinner
from time import sleep, time
from pathlib import Path
import json
import logging
import sys
import traceback
from multiprocessing import Process, Queue
from os import urandom
import base64

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
    curses.init_pair(4, curses.COLOR_MAGENTA, -1) #copyright

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
    theknwrt = None
    if "meinkennwort" not in datafile:
        win.clear()
        stdscr.border()
        newpass = ""
        while True:
            win.addstr("No master password detected\n\n", curses.color_pair(1))
            win.addstr("New Password:\n", curses.color_pair(1))
            win.addstr("> ", curses.color_pair(1))
            newpass = __readinput(win, True)
            win.addstr(f"\nConfirm password:\n", curses.color_pair(1))
            win.addstr("> ", curses.color_pair(1))
            confpass = __readinput(win, True)
            if newpass == confpass:
                break
            else:
                curses.curs_set(0)
                win.addstr("\nPasswords don't match!\n", curses.color_pair(3))
                _ = win.getch()
                win.clear()
        try:
            salt = urandom(16)
            meinkennwort = Queue()
            dk = PBKDF2(newpass, salt, _DEFAULTPBKDF2COUNT, 32)
            theknwrt=dk
            encpss = Process(target=__encryptpass, args=(dk, meinkennwort))
            encpss.start()
            frame = 0
            y, x = win.getyx()
            while encpss.is_alive() or meinkennwort.empty():
                if frame > 999:
                    frame = 0
                __loadingbar(win, "saving password", frame, y)
                frame+=1
            encpss.join()
            datafile["meinkennwort"] = meinkennwort.get()
            datafile["meinkennwort"]["salt"] = base64.b64encode(salt).decode("utf-8")

            __dumptodatafile(win, datafile)
        except Exception:
            win.addstr(f"\nFailed to set master password!\n", curses.color_pair(3))
            __crashhandler(win)
        win.addstr(f"\n\nMaster Password set successfully!\n", curses.color_pair(2))
        _ = win.getch()
        win.refresh()
        curses.flushinp()
    else:
        correct = False
        trycount = 0
        while not correct:
            trycount+=1
            if trycount > 5:
                win.addstr("Failed password check 5 times; press any key to close SmolTOP", curses.color_pair(3))
                _ = win.getch()
                sys.exit(0)
            win.addstr("Enter password\n", curses.color_pair(1))
            win.addstr("> ", curses.color_pair(1))
            passwd = __readinput(win, True)
            curses.curs_set(False)
            salt = base64.b64decode(datafile["meinkennwort"]["salt"].encode("utf-8"))
            dk = PBKDF2(passwd, salt, _DEFAULTPBKDF2COUNT, 32)
            encrpass = datafile["meinkennwort"]["data"]
            tag = datafile["meinkennwort"]["tag"]
            nonce = datafile["meinkennwort"]["nonce"]
            conf = __decrypt(dk, encrpass, tag, nonce, True)
            if dk != conf:
                win.addstr("\nincorrect\n", curses.color_pair(3))
                _ = win.getch()
            else:
                correct = True
                theknwrt=dk
            win.clear()
    win.clear()
    while True:
        datafile = __loaddatafile(win)
        curses.curs_set(True)
        curses.cbreak(False)
        win.addstr("SmolTOP 2FA Authenticator\n", curses.color_pair(1))
        win.addstr("Copyright 2026 @malachi196\n", curses.color_pair(4))
        win.addstr("\t1. Get TOTP\n", curses.color_pair(1))
        win.addstr("\t2. Register Application\n", curses.color_pair(1))
        win.addstr("\t3. Quit\n", curses.color_pair(1))
        win.addstr("> ", curses.color_pair(1))
        inpt = __readinput(win)
        match inpt:
            case "1":
                win.clear()
                if "apps" not in datafile:
                    win.addstr("No apps registered yet\n", curses.color_pair(1))
                    _ = win.getch()
                else:
                    win.addstr("Select application to authenticate:", curses.color_pair(1))
                    for i, (key, value) in enumerate(datafile["apps"].items()):
                        win.addstr(f"\n{i+1}. {key}", curses.color_pair(1))
                    win.addstr("\n> ", curses.color_pair(1))
                    choice = __readinput(win)
                    selected = False
                    name = ""
                    for i, (key, value) in enumerate(datafile["apps"].items()):
                        if choice == str(i+1):
                            name = str(key)
                            win.addstr(f"\n{key} selected") #DEBUG
                            selected = True
                            break
                    if not selected:
                        win.addstr(f"\n\"{choice}\" is not a valid choice!", curses.color_pair(3))
                        _ = win.getch()
                    else:
                        win.clear()
                        stpkeyencr = datafile["apps"][name]["data"]
                        nonce = datafile["apps"][name]["nonce"]
                        tag = datafile["apps"][name]["tag"]
                        stpkey = str(__decrypt(theknwrt, stpkeyencr, tag, nonce).decode("utf-8"))
                        curses.cbreak(False)
                        win.nodelay(True)
                        totp = TOTP(stpkey)
                        curses.curs_set(False)
                        while True:
                            win.erase()
                            l = win.getch()
                            epochleft = 30-(int(time())%30)
                            if epochleft > 29:
                                totp = TOTP(stpkey)
                            win.addstr(f"{name}\n" + len(name) * "-" + "\nTOTP: ", curses.color_pair(1))
                            win.addstr(f"{totp}\n", curses.color_pair(2))
                            win.addstr(f"Time till next TOTP: ", curses.color_pair(1))
                            win.addstr(f"{epochleft}s", curses.color_pair(2))
                            win.refresh()
                            if l != -1:
                                break
                            curses.napms(100)
                        win.nodelay(False)
                        curses.cbreak(True)
            case "2":
                win.clear()
                win.addstr("Name of app> ", curses.color_pair(1))
                appname = __readinput(win)
                win.addstr("\nSetup key> ", curses.color_pair(1))
                setupkey = __readinput(win)
                if "apps" not in datafile:
                    datafile["apps"] = {}
                encrkey = AES128(theknwrt, setupkey).encrypt()
                datafile["apps"][appname] = encrkey
                __dumptodatafile(win, datafile)
                win.addstr("\nApp registered successfully!\n", curses.color_pair(1))
                _ = win.getch()
            case "3":
                win.addstr("\nbye!\n", curses.color_pair(1))
                win.refresh()
                sleep(1)
                sys.exit()
            case _:
                win.addstr(f"\ninvalid option \"{inpt}\"", curses.color_pair(3))
                _ = win.getch()
        win.clear()
    
def __readinput(win:curses.window, passwd=False):
    curses.noecho()
    curses.cbreak(True)
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
        if passwd:
            win.addstr("*", curses.color_pair(2))
        else:
            win.addstr(chr(l), curses.color_pair(2))
    curses.cbreak(False)
    return newpass

def __loaddatafile(win:curses.window):
    try:
        with open(f"{THISPATH}/data/smltpksndpss.json", "r") as f:
            datafile = json.load(f)
        return datafile
    except json.decoder.JSONDecodeError as e:
        try:
            with open(f"{THISPATH}/data/smltpksndpss.json", "w") as f:
                f.write(r"{ }")
            with open(f"{THISPATH}/data/smltpksndpss.json", "r") as f:
                datafile = json.load(f)
            return datafile
        except json.decoder.JSONDecodeError:
            win.addstr("\nDatafile format was not readable!\n", curses.color_pair(3))
            __crashhandler(win)
    except Exception as e:
        win.addstr("\nError while trying to load datafile!\n", curses.color_pair(3))
        __crashhandler(win)

def __dumptodatafile(win, data):
    try:
        with open(f"{THISPATH}/data/smltpksndpss.json", "w") as f:
            json.dump(data, f, indent=4)
    except json.decoder.JSONDecodeError as e:
        win.addstr("\nDatafile format was not readable!\n", curses.color_pair(3))
        __crashhandler(win)
    except Exception as e:
        win.addstr("\nError while trying to dump to datafile!\n", curses.color_pair(3))
        __crashhandler(win)

def __loadingbar(win:curses.window, text, frame, y):
    nexty = y + 1
    win.addstr(nexty, 0, f"{text} {spinner[frame % len(spinner)]}", curses.color_pair(2))
    win.refresh()
    sleep(0.05)

def __crashhandler(win:curses.window):
    win.addstr("traceback saved to \"crash.log\"", curses.color_pair(3))
    e = traceback.format_exc()
    logging.error(e)
    curses.curs_set(False)
    win.timeout(-1)
    _ = win.getch()
    sys.exit(1)

def __encryptpass(dk, queue:Queue):
    encr = AES128(dk, dk).encrypt("base64")
    queue.put(encr)

def __decrypt(dk, data, tag, nonce, ispassundertest=False):  
    return AES128(dk, data).decrypt(tag, nonce, "base64", ispassundertest)

if __name__=="__main__":
    curses.wrapper(main)