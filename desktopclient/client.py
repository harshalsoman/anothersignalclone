import base64
import os
import pickle
import threading
import tkinter
import tkinter as tk
import tkinter.filedialog
import tkinter.font
import tkinter.messagebox
import traceback
from io import BytesIO
from tkinter import ttk

import requests
import websockets.sync.client
from PIL import Image, ImageTk

from protocols.double_ratchet import KeyStore, Ratchet

RECV_BUFFER = 10000000
users = {}
messages = {}
global contacts
with open('server_ip.txt', 'r') as file:
    ip_address = file.read().strip()


class Application(tkinter.Tk):
    def load_user_keys(self, folder_path):

        for file_name in os.listdir(folder_path):
            if file_name.endswith(".dat"):
                file_path = os.path.join(folder_path, file_name)
                username = os.path.splitext(file_name)[0]

                with open(file_path, 'rb') as file:
                    ratchet_key = pickle.load(file)

                users[username] = ratchet_key

    def launch_app(self):
        dat_file_path = "./store/kb.dat"
        dat_dir = os.path.dirname(dat_file_path)
        os.makedirs(dat_dir, exist_ok=True)

        if os.path.exists(dat_file_path):
            with open(dat_file_path, 'rb') as file:
                self.bob = pickle.load(file)


        users_folder_path = "users"
        os.makedirs(os.path.join(dat_dir, users_folder_path), exist_ok=True)

        self.load_user_keys('./store/users')

        self.title('Yet Another Signal Clone')

        self.frame = ttk.Frame(self)

        self.frame.style = ttk.Style()

        ttk.Style().configure("TButton", padding=6, relief="flat")
        self.reg_btn = ttk.Button(self.frame, text='New user?  Sign Up here!', command=self.reg_menu, takefocus=True)
        self.reg_btn.grid(row=2, column=2, padx=40, pady=30)
        self.client_button = ttk.Button(self.frame, text='Log In', command=self.client_menu, takefocus=True)
        self.client_button.grid(row=2, column=0, padx=40, pady=30)
        self.try_again_bool = False
        self.try_again_bool2 = False
        self.frame.pack(fill=tkinter.BOTH, expand=True)

        self.theme_use = 'classic'

        self.frame.style.theme_use(self.theme_use)

        self.mainloop()

    def reg_menu(self):
        if self.try_again_bool2:
            self.try_again2.destroy()
            self.un_error.destroy()
            self.try_again_bool2 = False
        self.client_button.destroy()
        self.reg_btn.destroy()
        self.host = ip_address
        self.port = 9000
        self.reg_name_label = ttk.Label(self.frame, text='Username', justify=tkinter.RIGHT)
        self.reg_name_entry = ttk.Entry(self.frame)
        self.reg_pwd_label = ttk.Label(self.frame, text="Password", justify=tkinter.RIGHT)
        self.reg_pwd_entry = ttk.Entry(self.frame, show='*')

        self.register_btn = ttk.Button(self.frame, text='Sign Up', command=self.reg_user, takefocus=True)

        self.frame.pack_forget()

        self.title('Registration')
        self.reg_name_label.grid(row=2, column=0, pady=10, padx=5, sticky=tkinter.E)
        self.reg_name_entry.grid(row=2, column=1, pady=10, padx=5)
        self.reg_pwd_label.grid(row=3, column=0, pady=10, padx=5, sticky=tkinter.E)
        self.reg_pwd_entry.grid(row=3, column=1, pady=10, padx=5)
        self.register_btn.grid(row=4, column=2, pady=10, padx=5)
        self.frame.pack(fill=tkinter.BOTH, expand=True)

    def reg_user(self):

        self.username = self.reg_name_entry.get().rstrip()
        self.password = self.reg_pwd_entry.get().rstrip()
        self.reg_name_label.destroy()
        self.reg_name_entry.destroy()
        self.reg_pwd_label.destroy()
        self.reg_pwd_entry.destroy()
        self.register_btn.destroy()
        self.frame.pack_forget()

        try:
            url = f'http://{ip_address}:8000/registration'
            var = requests.post(url,
                                data='username=' + self.username + '&password=' + self.password,
                                headers={'Content-Type': 'application/x-www-form-urlencoded'})
            var = var.status_code
            if var == 201:
                self.bob = KeyStore()
                ltk_pk, spk_pk, otpks = self.bob.get_key_bundle()
                spk_sig = self.bob.sign_spk()
                msg = ltk_pk + spk_pk + spk_sig
                b = b''
                for byte in otpks:
                    b += byte
                msg += b
                var = requests.post(f'http://{ip_address}:8000/keybundle/' + self.username,
                                    json={
                                        "key_bundle": base64.encodebytes(msg).decode()
                                    },
                                    headers={'Content-Type': 'application/json'})
                if var.status_code != 201:
                    self.reg_menu()
            else:
                print("Failure")
                self.reg_menu()

        except Exception as e:
            print(traceback.format_exc())
            self.reg_menu()
        self.client_menu()

    def client_menu(self):
        self.client_button.destroy()
        self.reg_btn.destroy()
        if self.try_again_bool:
            self.try_again.destroy()
            self.wp_error.destroy()
            self.try_again_bool = False

        self.title('Log In')
        self.name_entry_label = ttk.Label(self.frame, text='User name', anchor=tkinter.W, justify=tkinter.LEFT)
        self.name_entry = ttk.Entry(self.frame)
        self.pwd_entry_label = ttk.Label(self.frame, text='Password', anchor=tkinter.W, justify=tkinter.LEFT)
        self.pwd_entry = ttk.Entry(self.frame, show='*')
        self.launch_button = ttk.Button(self.frame, text='Log In', command=self.launch_client)
        self.name_entry_label.grid(row=2, column=0, pady=10, padx=5)
        self.name_entry.grid(row=2, column=1, pady=10, padx=5)
        self.pwd_entry_label.grid(row=3, column=0, pady=10, padx=5)
        self.pwd_entry.grid(row=3, column=1, pady=10, padx=5)
        self.launch_button.grid(row=5, column=1, pady=10, padx=5)

        self.frame.pack(fill=tkinter.BOTH, expand=True)

    def launch_client(self):
        try:
            self.host = ip_address
            self.port = 9000
            self.name = self.name_entry.get()
            self.pwd = self.pwd_entry.get()
            self.name_entry_label.destroy()
            self.name_entry.destroy()
            self.pwd_entry_label.destroy()
            self.pwd_entry.destroy()

            self.launch_button.destroy()
            self.frame.pack_forget()
            f = 0
            var = requests.post(f'http://{ip_address}:8000/authentication',
                                data='username=' + self.name + '&password=' + self.pwd,
                                headers={'Content-Type': 'application/x-www-form-urlencoded'})
            if var.status_code != 200:
                print("Failure to login")
                self.launch_client()
            self.flag = 0
            self.conn = websockets.sync.client.connect(f"ws://{ip_address}:9000")
            self.conn.send(self.name)

            self.title('Yet Another Signal Clone')
            self.should_quit = False
            self.protocol('WM_DELETE_WINDOW', self.client_quit)
            var = requests.get(f'http://{ip_address}:8000/messages/' + self.name,
                               headers={'Content-Type': 'application/json'})

            for msg in var.json()['messages']:
                if msg['type'] == 'x3dh':
                    sender = msg['by']
                    content = base64.decodebytes(msg['content'].encode())
                    (sk_bob, msg, ratchet_pub) = self.bob.x3dh_w_header(content[:128], content[128:])
                    if msg == sender + ' is requesting permission to chat':
                        users[sender] = Ratchet(sk_bob, dh_pub_key=ratchet_pub)
                        self.conn.send(sender)
                        self.conn.send('msg')
                        hdr, cph = users[sender].encrypt(self.name + ' has accepted your request to chat')
                        # new_security_code = users[sender].get_safety_number()
                        # self.update_security_code_label(new_security_code)
                        self.conn.send(hdr)
                        self.conn.send(cph)

                        if len(hdr) > 96:
                            otpk = hdr[96:]
                            if otpk in self.bob.otpk:
                                self.bob.otpk.remove(otpk)
                                ltk_pk, spk_pk, otpks = self.bob.get_key_bundle()
                                spk_sig = self.bob.sign_spk()
                                msg = ltk_pk + spk_pk + spk_sig
                                b = b''
                                for byte in otpks:
                                    b += byte
                                msg += b
                                requests.post(f'http://{ip_address}:8000/keybundle/' + self.username,
                                              json={
                                                  "key_bundle": base64.encodebytes(msg).decode()
                                              },
                                              headers={'Content-Type': 'application/json'})
                else:
                    sender = msg['by']
                    content = base64.decodebytes(msg['content'].encode())
                    if sender not in messages.keys():
                        messages[sender] = []
                    messages[sender].append(users[sender].decrypt(content[:128], content[128:]))
                    # new_security_code = users[sender].get_safety_number()
                    # self.update_security_code_label(new_security_code)
                var = requests.delete(f'http://{ip_address}:8000/messages/' + self.name)

            # STYLISING
            s = ttk.Style()
            s.configure("TButton", background='burlywood3')
            s.configure('my.TFrame', background='old lace')
            s.configure('new.TFrame', background='navajo white')
            s.configure('new1.TFrame', background='ivory2')
            s.configure("TLabelframe", background='old lace', highlightbackground='old lace')

            # Frames Used in Chat Window
            self.chat_frame = ttk.Frame(self.frame, borderwidth=5, style='my.TFrame')  # for the actual display of chat
            self.clients_frame = ttk.Frame(self.frame, style='my.TFrame')  # for radio buttons
            self.entry_frame = ttk.Frame(self, style='my.TFrame')  # for input text
            self.button_frame = ttk.Frame(self.entry_frame, style='my.TFrame')

            # Fonts Used in Chat Window
            fonte = tkinter.font.Font(family='Arial', size=16, weight=tkinter.font.BOLD)
            s.configure('.', font=fonte)
            font1 = tkinter.font.Font(family="Comic Sans MS", size=16, weight=tkinter.font.BOLD)
            font2 = tkinter.font.Font(family="Arial", size=16, weight=tkinter.font.BOLD)
            self.font3 = tkinter.font.Font(family="Courier New", size=16, weight=tkinter.font.BOLD)
            self.chat_font = tkinter.font.Font(family="Helvetica", size=18, weight=tkinter.font.BOLD)
            self.chat_text = tkinter.Text(self.chat_frame, state=tkinter.DISABLED)
            self.scroll = tkinter.Scrollbar(self.chat_frame)
            self.scroll.configure(command=self.chat_text.yview)
            self.chat_text.configure(yscrollcommand=self.scroll.set)

            # TAKING THE IMAGES REQUIRED FOR CHAT ICONS
            self.img = ImageTk.PhotoImage(Image.open('Images/send2.png'))
            self.img1 = ImageTk.PhotoImage(Image.open('Images/file.png'))
            self.img2 = ImageTk.PhotoImage(Image.open('Images/user.png'))

            # MESSAGE ENTRY WINDOW
            self.chat_entry = ttk.Entry(self.entry_frame, font=font2)  # Text Entry Widget
            self.scroll1 = tkinter.Scrollbar(self.entry_frame, orient=tkinter.HORIZONTAL)  # Adding ScrollBar
            self.scroll1.configure(command=self.chat_entry.xview)
            self.chat_entry.configure(xscrollcommand=self.scroll1.set)
            self.send_button = ttk.Button(self.button_frame, image=self.img)
            self.browsebutton = ttk.Button(self.button_frame, image=self.img1,
                                           command=self.browse)
            self.send_button.bind('<Button-1>', self.send)
            self.chat_entry.bind('<Return>', self.send)

            # CLIENT FRAME
            self.user_icon = ttk.Label(self.clients_frame, image=self.img2, background='light blue', text=self.name,
                                       compound="top", font=self.font3, anchor=tkinter.E)
            self.frame.pack(side=tkinter.TOP, fill=tkinter.BOTH,
                            expand=True)
            self.user_icon.pack(side=tkinter.TOP)

            # SERVER INFO
            # self.server_l=ttk.Labelframe(self.clients_frame,text="Server Info",labelanchor=tkinter.NW,padding=20,borderwidth=2)
            # self.server_info1=ttk.Label(self.server_l,background='old lace',text="Server IP : "+self.host+'\n\n'+"Server Port: "+str(self.port),font=self.font3)
            # self.server_l.pack(side=tkinter.TOP,pady=40)
            # self.server_info1.pack()

            # TAB SECTION
            s.configure('TNotebook', background='old lace', borderwidth=1)
            self.tabs = ttk.Notebook(self.clients_frame, height=20, padding=10)
            self.tabs.pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=True)
            self.f1 = ttk.Frame(self.clients_frame, style="new.TFrame")
            self.f2 = ttk.Frame(self.clients_frame, style="new1.TFrame")
            self.tabs.add(self.f1, text="Security Code")
            self.tabs.add(self.f2, text="Contacts")

            self.security_code_label = ttk.Label(self.f1, text="Security Code: ", font=self.font3,
                                                 foreground='gray49', background='old lace')
            self.security_code_label.grid(row=0, column=0, sticky=tkinter.W)

            # CONTACTS#

            self.contact_label = [];
            self.selected_contact = tkinter.StringVar()
            self.contact_combobox = ttk.Combobox(self.f2, textvariable=self.selected_contact, font=self.font3,
                                                 foreground='gray49', background='old lace')
            self.contact_combobox.grid(row=0, column=0, sticky=tkinter.W)
            var = requests.get(f'http://{ip_address}:8000/users',
                               headers={'Content-Type': 'application/json'})
            var = var.json()['users']
            self.contacts = []
            self.contacts_with_status = []
            for user in var:
                if self.name == user['user']:
                    continue
                self.contacts.append(user['user'])
                if user['active']:
                    self.contacts_with_status.append(user['user'] + ' *')
                else:
                    self.contacts_with_status.append(user['user'])
            self.num_contacts = len(var) - 1

            self.contact_combobox['values'] = self.contacts_with_status
            # Bind a callback function to handle selection changes
            self.contact_combobox.bind("<<ComboboxSelected>>", self.handle_contact_selection)

            # PACKING ABOVE CREATED widgets                      #The order of packing of widgets may be arbitrary to ensure proper layout.
            self.clients_frame.pack(side=tkinter.LEFT, fill=tkinter.BOTH, expand=True)
            self.chat_frame.pack(side=tkinter.RIGHT, fill=tkinter.BOTH, expand=True)
            self.send_button.pack(side=tkinter.LEFT, fill=tkinter.BOTH, expand=True)
            self.browsebutton.pack(side=tkinter.LEFT, fill=tkinter.BOTH, expand=True)
            self.button_frame.pack(side=tkinter.RIGHT)
            self.scroll1.pack(side=tkinter.BOTTOM, fill=tkinter.X)
            self.chat_entry.pack(side=tkinter.LEFT, fill=tkinter.BOTH, expand=True)
            self.entry_frame.pack(side=tkinter.BOTTOM, fill=tkinter.X)
            self.scroll.pack(side=tkinter.RIGHT, fill=tkinter.Y)
            self.chat_text.pack(fill=tkinter.BOTH, expand=True)
            self.chat_entry.focus_set()
            self.clientchat_thread = threading.Thread(name='clientchat',
                                                      target=self.clientchat)
            self.clientchat_thread.start()
        except Exception:
            print(traceback.format_exc())

        # self.clientchat_thread.join()

    # Define a method to update the security code label
    def update_security_code_label(self, new_security_code):
        self.security_code_label.config(text=new_security_code)

    def clear_chat_display(self):
        self.chat_text.config(state=tkinter.NORMAL)
        self.chat_text.delete('1.0', tkinter.END)

    def handle_contact_selection(self, event):
        selected_contact = self.selected_contact.get()
        if '*' in selected_contact:
            selected_contact = selected_contact[:-2]

        self.clear_chat_display()

        if selected_contact not in users:
            var = requests.get(f'http://{ip_address}:8000/keybundle/' + selected_contact,
                               headers={'Content-Type': 'application/x-www-form-urlencoded'})
            bundle = base64.decodebytes(var.json()['key_bundle'].encode())
            ltk = bundle[:32]
            spk = bundle[32:64]
            sig = bundle[64:128]
            arr = []

            _sum = 128
            while _sum + 32 >= len(bundle):
                arr.append(bundle[_sum:_sum + 32])
                _sum = _sum + 32

            arr = arr[0] if len(arr) else None
            (sk_alice, header, cipher, ratchet_pair) = self.bob.x3dh_w_key_bundle(
                self.name + ' is requesting permission to chat', (ltk, spk, sig, arr))
            users[selected_contact] = Ratchet(sk_alice, ratchet_pair)

            self.conn.send(selected_contact)
            self.conn.send('x3dh')
            self.conn.send(header)
            self.conn.send(cipher)

            self.chat_text.config(state=tkinter.NORMAL)
            self.chat_text.insert(tkinter.END,
                                  'Waiting for ' + selected_contact + ' to accept request to chat...' + '\n',
                                  ('tag{0}'.format(2)))
            self.chat_text.tag_config('tag{0}'.format(2), justify=tkinter.LEFT, foreground='gray30',
                                      font=self.chat_font)
            self.chat_text.config(state=tkinter.DISABLED)
            self.chat_text.see(tkinter.END)

        if selected_contact in messages:
            for msg in messages[selected_contact]:
                self.chat_text.config(state=tkinter.NORMAL)
                self.chat_text.insert(tkinter.END, msg + '\n', ('tag{0}'.format(2)))
                self.chat_text.tag_config('tag{0}'.format(2), justify=tkinter.LEFT, foreground='gray30',
                                          font=self.chat_font)
                self.chat_text.config(state=tkinter.DISABLED)
                self.chat_text.see(tkinter.END)

    def browse(self):
        self.mmfilename = tkinter.filedialog.askopenfilename()
        self.multimedia_send()

    def send(self, event):
        message = self.chat_entry.get()
        contact = self.selected_contact.get()
        if '*' in contact:
            contact = contact[:-2]
        header, cipher = users[contact].encrypt(message)
        self.update_security_code_label(users[contact].get_safety_number())
        self.conn.send(contact)
        self.conn.send('msg')
        self.conn.send(header)
        self.conn.send(cipher)
        self.chat_entry.delete(0, tkinter.END)
        self.chat_text.config(state=tkinter.NORMAL)
        self.chat_text.insert(tkinter.END, self.name + ':' + message + '\n', ('tag{0}'.format(1)))
        self.chat_text.tag_config('tag{0}'.format(1), justify=tkinter.RIGHT, foreground='RoyalBlue3',
                                  font=self.chat_font)
        self.chat_text.config(
            state=tkinter.DISABLED)
        self.chat_text.see(tkinter.END)

    def multimedia_send(self):
        # Check if mmfilename is available
        if self.mmfilename:
            contact = self.selected_contact.get()
            if '*' in contact:
                contact = contact[:-2]

            # Read the image file and store the binary data
            with open(self.mmfilename, 'rb') as f:
                image_data1 = base64.b64encode(f.read()).decode()
                # Decode the base64 string to binary image data
            binary_data = base64.b64decode(image_data1)
            image_data = BytesIO(binary_data)
            image = Image.open(image_data)

            # Resize the image maintaining aspect ratio
            max_width, max_height = 300, 300
            original_width, original_height = image.size
            ratio = min(max_width / original_width, max_height / original_height)
            new_width = int(original_width * ratio)
            new_height = int(original_height * ratio)

            # Resize using the appropriate method
            try:
                from PIL import ImageResampling
                image = image.resize((new_width, new_height), ImageResampling.LANCZOS)
            except ImportError:
                image = image.resize((new_width, new_height), Image.LANCZOS)

            # Convert the PIL image object to a format that Tkinter can use
            photo = ImageTk.PhotoImage(image)

            # Display the image in the sender's chat window
            self.display_image(image_data1, sender=True)

            # Encrypt and send the image data
            header, cipher = users[contact].encrypt("Image" + image_data1)
            self.update_security_code_label(users[contact].get_safety_number())
            self.conn.send(contact)
            self.conn.send('msg')
            self.conn.send(header)
            self.conn.send(cipher)

            # Reset mmfilename after sending
            self.mmfilename = None
        else:
            print("No multimedia file selected.")

    def clientchat(self):
        while not self.should_quit:
            try:
                sender = self.conn.recv()
                type = self.conn.recv()

                if sender == 'server' and type == 'add':
                    new_contact = self.conn.recv()
                    if new_contact not in self.contacts:
                        self.contacts.append(new_contact)
                    if new_contact + ' *' not in self.contacts_with_status and new_contact in self.contacts_with_status:
                        self.contacts_with_status.remove(new_contact)
                        self.contacts_with_status.append(new_contact + ' *')
                    elif new_contact not in self.contacts_with_status:
                        self.contacts_with_status.append(new_contact + ' *')

                    self.contact_combobox['values'] = self.contacts_with_status

                elif sender == 'server' and type == 'remove':
                    new_contact = self.conn.recv()
                    self.contacts_with_status.remove(new_contact + ' *')
                    self.contacts_with_status.append(new_contact)
                    self.contact_combobox['values'] = self.contacts_with_status

                elif type == 'x3dh':
                    header = self.conn.recv()
                    cipher = self.conn.recv()
                    (sk_bob, msg, ratchet_pub) = self.bob.x3dh_w_header(header, cipher)
                    if msg == sender + ' is requesting permission to chat':
                        users[sender] = Ratchet(sk_bob, dh_pub_key=ratchet_pub)

                        self.conn.send(sender)
                        self.conn.send('msg')
                        hdr, cph = users[sender].encrypt(self.username + ' has accepted your request to chat')
                        new_security_code = users[sender].get_safety_number()

                        self.update_security_code_label(new_security_code)
                        self.conn.send(hdr)
                        self.conn.send(cph)
                        continue

                else:
                    header = self.conn.recv()
                    cipher = self.conn.recv()
                    msg = users[sender].decrypt(header, cipher)
                    new_security_code = users[sender].get_safety_number()
                    self.update_security_code_label(new_security_code)
                    contact = self.selected_contact.get()
                    if '*' in contact:
                        contact = contact[:-2]
                    # Check if the message is an image

                    if sender == contact:
                        if msg.startswith("Image"):
                            image_data = msg[len("Image"):]
                            self.display_image(image_data)
                        else:
                            self.display_text_message(sender, msg)
                    else:
                        if sender not in messages.keys():
                            messages[sender] = []
                        messages[sender].append(msg)

            except Exception as e:
                print(traceback.format_exc())
                continue

    def display_text_message(self, sender, message):
        self.chat_text.config(state=tkinter.NORMAL)
        self.chat_text.insert(tkinter.END, sender + ':' + message + '\n', ('tag{0}'.format(2)))
        self.chat_text.tag_config('tag{0}'.format(2), justify=tkinter.LEFT, foreground='gray30',
                                  font=self.chat_font)
        self.chat_text.config(state=tkinter.DISABLED)
        self.chat_text.see(tkinter.END)

    def display_image(self, image_data, sender=False):
        # Decode the base64 string to binary image data
        binary_data = base64.b64decode(image_data)
        image_data = BytesIO(binary_data)
        image = Image.open(image_data)

        # Resize the image maintaining aspect ratio
        max_width, max_height = 400, 400
        original_width, original_height = image.size
        ratio = min(max_width / original_width, max_height / original_height)
        new_width = int(original_width * ratio)
        new_height = int(original_height * ratio)

        # Resize using the appropriate method
        try:
            from PIL import ImageResampling
            image = image.resize((new_width, new_height), ImageResampling.LANCZOS)
        except ImportError:
            image = image.resize((new_width, new_height), Image.LANCZOS)

        # Convert the PIL image object to a format that Tkinter can use
        photo = ImageTk.PhotoImage(image)

        # Create a label that will hold the image
        image_label = tk.Label(self.chat_text, image=photo, bg='white')
        image_label.image = photo  # keep a reference!

        # Insert a newline to ensure the label is on a new line
        self.chat_text.insert(tk.END, '\n')

        # Insert the label into the text widget
        self.chat_text.window_create(tk.END, window=image_label)

        # Apply tag configurations for alignment
        if sender:
            self.chat_text.tag_add("right", "end-1l linestart", "end-1l lineend")
            self.chat_text.tag_configure("right", justify='right')
        else:
            self.chat_text.tag_add("left", "end-1l linestart", "end-1l lineend")
            self.chat_text.tag_configure("left", justify='left')

        # Ensure the chat text scrolls to the end
        self.chat_text.see(tk.END)
        # Disable editing
        self.chat_text.config(state=tk.DISABLED)

    def client_quit(self):

        if tkinter.messagebox.askokcancel(title="Quit Window", message="Do you really want to quit?"):
            if self.bob:
                directory = './store'
                if not os.path.exists(directory):
                    os.makedirs(directory)

                # Specify the file path
                file_path = os.path.join(directory, 'kb.dat')

                # Serialize and save the key bundle
                with open(file_path, 'wb') as file:
                    pickle.dump(self.bob, file)

            if len(users.keys()) != 0:
                if not os.path.exists('./store/users'):
                    os.makedirs('./store/users')

                # Specify the file path
                for user in users.keys():
                    file_path = os.path.join('./store/users', user + '.dat')

                    # Serialize and save the key bundle
                    with open(file_path, 'wb') as file:
                        pickle.dump(users[user], file)
            self.should_quit = True
            self.conn.close()
            self.clientchat_thread.join()
            self.destroy()

        else:
            pass


if __name__ == '__main__':
    app = Application()
    app.launch_app()

