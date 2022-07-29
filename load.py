import time
from base64 import b64encode
from typing import Optional, Tuple, Dict, Any
import tkinter as tk
from ttkHyperlinkLabel import HyperlinkLabel
import socket
from threading import Thread

import myNotebook as nb
import requests
from theme import theme

from config import config


PLATFORM_OPTIONS = ["pc", 'ps', "xb"]

class This:
    system:Optional[str]=config.get_str("system")
    jump_range:Optional[int]=config.get_int("jump_range")
    parent: Optional[tk.Frame] = None

    frame: Optional[tk.Frame] = None

    token: Optional[str] = config.get_str("oauth_token")

    status_widget: Optional[tk.Label]=None

    odyssey: Optional[bool] = config.get_bool("odyssey")
    platform: Optional[int] = config.get_int("platform")

    odyssey_var: Optional[tk.BooleanVar] = None
    platform_var: Optional[tk.StringVar] = None
    range_var:Optional[tk.IntVar] = None

    rescues: Optional[dict]= {"rescues":[]}


this = This()

def get_rescues_thread():
    time.sleep(15)
    def create_rescue(cr,ody,plat,system,id,taken,jumps,job_id):
        return {'code_red':cr,"odyssey":ody,"platform":plat,"system":system,"id":id,"taken":taken,"jumps":jumps,"job_id":job_id}

    headers = {
        "authorization": f"Bearer {this.token}"
    }
    while True:
        if not config.get_bool("working"):
            return 0
        if not this.token:
            time.sleep(20)
            continue
        res = requests.get("https://api.fuelrats.com/rescues?filter%5Bstatus%5D%5Bne%5D=closed&sort=-createdAt",
                       headers=headers)
        if not res.status_code==200:
            time.sleep(20)
            continue
        rescues_list = []
        rescues = res.json()['data']
        new_rescues_list = []

        for rescue in rescues:
            attrs = rescue['attributes']
            if attrs['status']!="open":
                continue
            cr = attrs['codeRed']
            id = attrs['commandIdentifier']
            plat = attrs['platform']
            ody = attrs['odyssey']
            system = attrs['system']
            taken = False
            for quote in attrs['quotes']:
                if f"#{id}" in quote['message'] and "j" in quote['message']:
                    taken = True
            body = {
                "efficiency": 100,
                "range": this.jump_range,
                "from": this.system,
                "to": system
            }
            res = requests.post('https://www.spansh.co.uk/api/route',data=body)
            job_id = res.json()['job']
            resc = create_rescue(cr,ody,plat,system,id,taken,0,job_id)
            rescues_list.append(resc)

        ready = False
        while not ready:
            time.sleep(2)
            ready=True
            for rescue in rescues_list:
                resp = requests.get(f"https://www.spansh.co.uk/api/results/{rescue['job_id']}").json()
                if not "result" in resp:
                    ready=False


        for rescue in rescues_list:
            resp = requests.get(f"https://www.spansh.co.uk/api/results/{rescue['job_id']}").json()['result']['system_jumps']
            jumps = 0
            for jump in resp:
                jumps+=jump['jumps']
            rescue['jumps']=jumps
            rescue['job_id']=""
            new_rescues_list.append(rescue)

        if this.rescues['rescues']!=new_rescues_list:
            this.rescues['rescues']=new_rescues_list
            draw_this_frame()





def set_prefs(parent):
    this.odyssey_var = tk.BooleanVar(value = this.odyssey)
    this.range_var = tk.IntVar(value=this.jump_range)
    try:
        this.platform_var = tk.StringVar(value = PLATFORM_OPTIONS[this.platform])
    except:
        this.platform_var = tk.StringVar(value = None)



def plugin_prefs(parent: nb.Notebook, cmdr: str, is_beta: bool) -> Optional[tk.Frame]:
    auth_uri = 'https://fuelrats.com/authorize?response_type=code&client_id=8e2c64b6-553a-4c26-b1b7-38a4c7776d87&scope=rescues.read&redirect_uri=http%3A%2F%2Flocalhost%3A10808&state=11'


    frame = nb.Frame(parent)

    HyperlinkLabel(frame, text='FuelRats plugin', background=nb.Label().cget('background'),
                   url="https://github.com/juiceofglass/FuelRats/", underline=True).grid(row=0,column=0, columnspan=2, pady=2, sticky=tk.W)
    HyperlinkLabel(frame, text='FuelRats Website', background=nb.Label().cget('background'),
                   url="https://fuelrats.com", underline=True).grid(row=0,column=0, columnspan=2, pady=2, sticky=tk.W)

    if not this.token:
        HyperlinkLabel(frame, text='Authorize your fuelrats account', background=nb.Label().cget('background'), url=auth_uri, underline=True).grid(row=1, columnspan=2, padx=2, sticky=tk.W)

    nb.Label(frame, text='Platform').grid(row=2, sticky=tk.W)
    nb.OptionMenu(frame, this.platform_var, this.platform_var.get(), *PLATFORM_OPTIONS).grid(row=2, column=1, columnspan=2,sticky=tk.W)
    nb.Checkbutton(frame, text="Odyssey", variable=this.odyssey_var).grid(row=3,column=0,sticky=tk.W)


    nb.Label(frame, text='Jump range').grid(row=4, column=0,sticky=tk.W)
    nb.Entry(frame, textvariable=this.range_var).grid(row=4, column=1,sticky=tk.W)

    theme.update(frame)
    return frame

def prefs_changed(cmdr: str, is_beta: bool) -> None:
   """
   Save settings.
   """
   this.jump_range = this.range_var.get()
   this.platform = PLATFORM_OPTIONS.index(this.platform_var.get())
   this.odyssey = bool(this.odyssey_var.get())
   config.set("platform",PLATFORM_OPTIONS.index(this.platform_var.get()))
   config.set("odyssey",bool(this.odyssey_var.get()))
   config.set('jump_range',this.range_var.get())
   draw_this_frame()

def setclipboard(text):
    r = tk.Tk()
    r.clipboard_clear()
    r.clipboard_append(text)
    r.destroy()

def draw_this_frame():
    for widget in this.frame.winfo_children():
        widget.destroy()
    label = tk.Label(this.frame, text="FuelRats Plugin")
    label.grid(row=0, column=0, columnspan=2, sticky=tk.W)

    new_widget_1 = tk.Label(this.frame, text="Status:")
    new_widget_1.grid(row=1, column=0, sticky=tk.W)

    if not this.token:
        this.status_widget = tk.Label(this.frame, text="Unauthorized!",
                                      foreground="red")  # Override theme's foreground color
        this.status_widget.grid(row=1, column=1, sticky=tk.W)
    else:
        this.status_widget = tk.Label(this.frame, text="Authorized!",
                                      foreground="green")  # Override theme's foreground color
        this.status_widget.grid(row=1, column=1, sticky=tk.W)

    col_label = tk.Label(this.frame, text=f"Jump range: {this.jump_range}")
    col_label.grid(row=1, column=3,columnspan=2,  sticky=tk.E)
    col_label = tk.Label(this.frame, text=f"Current system: {this.system}")
    col_label.grid(row=1, column=5,columnspan=2,  sticky=tk.E)

    if this.token:
        col_label = tk.Label(this.frame, text="Cases:")
        col_label.grid(row=2, column=0, columnspan=2, sticky=tk.W)
        id_label = tk.Label(this.frame, text="Case id:")
        id_label.grid(row=3, column=0,  sticky=tk.W)
        cr_label = tk.Label(this.frame, text="Code Red:")
        cr_label.grid(row=3, column=1,  sticky=tk.W)
        system_label = tk.Label(this.frame, text="System:")
        system_label.grid(row=3, column=2,  sticky=tk.W)
        platform_label = tk.Label(this.frame, text="Platform:")
        platform_label.grid(row=3, column=3, sticky=tk.W)
        ody_label = tk.Label(this.frame, text="Odyssey:")
        ody_label.grid(row=3, column=4, sticky=tk.W)
        taken_label = tk.Label(this.frame, text="Taken:")
        taken_label.grid(row=3, column=5, sticky=tk.W)
        jumps_label = tk.Label(this.frame, text="Jumps:")
        jumps_label.grid(row=3, column=6, sticky=tk.W)
        jcall_label = tk.Label(this.frame, text="Call jumps:")
        jcall_label.grid(row=3, column=7, sticky=tk.W)


        def call_jumps(id,jumps):
            setclipboard(f"#{id} {jumps}j")
        for row,rescue in enumerate(this.rescues['rescues']):
            row = row+4
            id_info = tk.Label(this.frame, text="#"+str(rescue['id']))
            id_info.grid(row=row, column=0, sticky=tk.W)
            cr_info = tk.Label(this.frame, text=("y" if rescue['code_red'] else 'n'),foreground=("red" if rescue['code_red'] else "green"))
            cr_info.grid(row=row, column=1, sticky=tk.W)
            system_info= tk.Button(this.frame, text = rescue['system'], command = lambda a=rescue['system']: setclipboard(a))
            system_info.grid(row=row, column=2, sticky=tk.W)
            platform_info = tk.Label(this.frame, text=rescue['platform'],foreground=("green" if rescue['platform']==PLATFORM_OPTIONS[this.platform] else "red"))
            platform_info.grid(row=row, column=3, sticky=tk.W)
            ody_info = tk.Label(this.frame, text=("y" if rescue['odyssey'] else 'n'),foreground=("green" if rescue['odyssey']==this.odyssey else "red"))
            ody_info.grid(row=row, column=4, sticky=tk.W)
            taken_info = tk.Label(this.frame, text=("y" if rescue['taken'] else 'n'),foreground=("red" if rescue['taken'] else "green"))
            taken_info.grid(row=row, column=5, sticky=tk.W)
            jumps_info = tk.Label(this.frame, text=rescue['jumps'])
            jumps_info.grid(row=row, column=6, sticky=tk.W)
            jcall_info = tk.Button(this.frame, text = 'Call jumps', command = lambda a=rescue['id'],b=rescue['jumps']: call_jumps(a,b))
            jcall_info.grid(row=row, column=7, sticky=tk.W)
    theme.update(this.frame)

def plugin_app(parent: tk.Frame) -> tk.Frame:
    """
    Create a frame for the EDMarketConnector main window
    """
    this.parent = parent  # system label in main window
    this.parent.bind('<<RatInfoUpdate>>', draw_this_frame)

    this.frame = tk.Frame(parent)
    this.frame.focus_set()
    draw_this_frame()
    set_prefs(parent)

    return this.frame

def journal_entry(cmdr: str, is_beta: bool, system: str, station: str, entry: Dict[str, Any], state: Dict[str, Any]) -> None:
    print(entry)
    if this.system!=system:
        if system:
            this.system=system
            config.set("system",system)
            draw_this_frame()


    if entry['event'] == 'FSDJump':
        this.system=entry['StarSystem']
        config.set("system", system)
        draw_this_frame()

    this.parent.event_generate('<<RatInfoUpdate>>', when="tail")


def start_server():
    HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
    PORT = 10808  # Port to listen on (non-privileged ports are > 1023)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        data = conn.recv(1024).decode('utf-8').split("\r\n")[0]

        conn.send(b'HTTP/1.0 200 OK\r\n')
        conn.send(
            b'Content-Type: text/html; charset=utf-8\r\nContent-Length: 52\r\nServer: Werkzeug/2.0.2 Python/3.9.6\r\nDate: Thu, 28 Jul 2022 11:12:02 GMT\r\n\r\n')
        conn.send(b'<h1>Authorized, you can close this window now</h1>')

    if "state=11" not in data:
        quit(1)
    code = data[data.find("=") + 1:data.find("&")]
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://localhost:10808"
    }
    client_id = "8e2c64b6-553a-4c26-b1b7-38a4c7776d87"
    client_secret = "WguYJtfQABJnvPCH3qLXvwJA0Dd0Z5Om"
    headers = {
        "Authorization": f"Basic {b64encode((client_id + ':' + client_secret).encode('utf-8')).decode('utf-8')}"
    }
    res = requests.post('https://api.fuelrats.com/oauth2/token', data=data, headers=headers)
    this.token = res.json()['access_token']
    config.set("oauth_token", this.token)


def plugin_start3(plugin_dir, *args, **kwargs) -> str:
    if not this.token:
        t1 = Thread(target=start_server)
        t1.start()
    config.set("working",True)
    t2 = Thread(target=get_rescues_thread)
    t2.start()


    return "FuelRats"

def plugin_stop():
    config.set("working",False)