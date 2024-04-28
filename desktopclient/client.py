import time
import sys
import socket  # Importing the socket module
import tkinter  # The python gui interface for Tk gui extension we 're using
from tkinter import ttk  # Module providing access to the Tk themed widget set
import tkinter.messagebox
import tkinter.font
import tkinter.filedialog
from PIL import ImageTk, Image  # Importing the Python Imaging Library (Pillow)
import threading  # Module for high-level threading api in python
import base64  # Module for accessing base64 encoding features

# Every ttk object (representing a gui object..sort of) in the class has a style object associated with it for formatting, styling and beautification
# Entries are objects which appear like text boxes and we can take entries inside them,
# Labels are non modifiable objects that are just used to just mention or label other objects
# Buttons are objects that have a click functionaity which is on an event of a click can call some functions
# .grid functions are used to position the different objects that are created the before objects
RECV_BUFFER = 10000000  # Data recieved


class Application(tkinter.Tk):

    def launch_app(self):  # default function always run to generate the main
        self.title('Yet Another Signal Clone')  # Name of our Application

        self.frame = ttk.Frame(self)  # A default object frame of the Frame class of the ttk library

        self.frame.style = ttk.Style()

        # Initial frame contains two buttons: One for registration and one for Log In
        ttk.Style().configure("TButton", padding=6, relief="flat")
        self.reg_btn = ttk.Button(self.frame, text='New user?  Sign Up here!', command=self.reg_menu, takefocus=True)
        self.reg_btn.grid(row=2, column=2, padx=40, pady=30)
        self.client_button = ttk.Button(self.frame, text='Log In', command=self.client_menu, takefocus=True)
        self.client_button.grid(row=2, column=0, padx=40, pady=30)
        self.try_again_bool = False
        self.try_again_bool2 = False
        # Command that integrates different objects into a single parent object.
        self.frame.pack(fill=tkinter.BOTH, expand=True)

        self.theme_use = 'classic'

        self.frame.style.theme_use(self.theme_use)

        # mailoop command keeps on running this for some time continuously, else it disappears.
        self.mainloop()

    # The Registration Menu
    def reg_menu(self):
        # Previous menu's buttons destroyed
        if self.try_again_bool2:
            self.try_again2.destroy()
            self.un_error.destroy()
            self.try_again_bool2 = False
        self.client_button.destroy()
        self.reg_btn.destroy()

        # Entries of this frame are host, port name and password and corresponding labels and entries are created
        # self.host_entry_label = ttk.Label(self.frame, text = 'Server IP Address', justify = tkinter.RIGHT)
        # self.host_entry = ttk.Entry(self.frame)
        # self.port_entry_label = ttk.Label(self.frame, text = 'Port Number', justify = tkinter.RIGHT)
        # self.port_entry = ttk.Entry(self.frame)
        self.host = "127.0.0.1"  # Hardcoded IP address
        self.port = 8000
        self.reg_name_label = ttk.Label(self.frame, text='Username', justify=tkinter.RIGHT)
        self.reg_name_entry = ttk.Entry(self.frame)
        self.reg_pwd_label = ttk.Label(self.frame, text="Password", justify=tkinter.RIGHT)
        self.reg_pwd_entry = ttk.Entry(self.frame, show='*')

        # Register Button
        self.register_btn = ttk.Button(self.frame, text='Sign Up', command=self.reg_user, takefocus=True)

        # Forgetting the previous packed Buttons
        self.frame.pack_forget()

        self.title('Registration')

        # Positioning the labels and text boxes appropriately
        # self.host_entry_label.grid(row=0, column=0, pady=10,padx=5,sticky=tkinter.E)
        # self.host_entry.grid(row=0, column=1, pady=10,padx =5)
        # self.port_entry_label.grid(row=1,column=0,pady=10,padx=5,sticky=tkinter.E)
        # self.port_entry.grid(row=1,column=1,pady=10,padx=5)
        self.reg_name_label.grid(row=2, column=0, pady=10, padx=5, sticky=tkinter.E)
        self.reg_name_entry.grid(row=2, column=1, pady=10, padx=5)
        self.reg_pwd_label.grid(row=3, column=0, pady=10, padx=5, sticky=tkinter.E)
        self.reg_pwd_entry.grid(row=3, column=1, pady=10, padx=5)
        self.register_btn.grid(row=4, column=2, pady=10, padx=5)

        # self.host_entry.focus_set()                                                     # to decide where the cursor is set
        # self.register_btn.focus_set()

        self.frame.pack(fill=tkinter.BOTH, expand=True)

    # Registering a new user
    def reg_user(self):
        # self.host = self.host_entry.get()
        # self.port = self.port_entry.get()
        # self.port = int(self.port)
        self.username = self.reg_name_entry.get().rstrip()
        self.password = self.reg_pwd_entry.get().rstrip()

        # delete the objects created in the frame that it was called into
        # self.host_entry_label.destroy()
        # self.host_entry.destroy()
        # self.port_entry_label.destroy()
        # self.port_entry.destroy()
        self.reg_name_label.destroy()
        self.reg_name_entry.destroy()
        self.reg_pwd_label.destroy()
        self.reg_pwd_entry.destroy()
        self.register_btn.destroy()
        self.frame.pack_forget()

        # creating socket for client and connecting with it the socket using the host IP and the host port

        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.conn.connect((self.host, self.port))  # Connected with the host at port number 'port'
        except:
            self.reg_menu()  # create the previous window again since the connection was not successful

        try:
            self.conn.send(str.encode(
                self.username + ' ' + self.password))  # Sending username and password for storing in the database
        except:
            self.reg_menu()  # Failing to send the username and password

        conf = self.conn.recv(4096).decode('utf-8')
        if (conf == "Error"):

            self.un_error = ttk.Label(self.frame, text='Username already used', anchor=tkinter.CENTER,
                                      justify=tkinter.CENTER)
            self.try_again2 = ttk.Button(self.frame, text='Try again', command=self.reg_menu)
            self.un_error.grid(row=0, column=1, pady=10, padx=5)
            self.try_again2.grid(row=1, column=1, pady=10, padx=5)
            self.try_again_bool2 = True
            self.frame.pack(fill=tkinter.BOTH, expand=True)

        else:
            self.client_menu()

    # The Log in menu
    def client_menu(self):
        # Preious buttons destroyed
        self.client_button.destroy()
        self.reg_btn.destroy()
        if self.try_again_bool:
            self.try_again.destroy()
            self.wp_error.destroy()
            self.try_again_bool = False

        self.title('Log In')

        # Entries of this frame are host, port name and password and corresponding labels and entries are created
        # self.host_entry_label = ttk.Label(self.frame, text = 'Server IP Address', anchor = tkinter.W, justify = tkinter.LEFT)
        # self.host_entry = ttk.Entry(self.frame)
        # self.port_entry_label = ttk.Label(self.frame, text = 'Port Number', anchor = tkinter.W, justify = tkinter.LEFT)
        # self.port_entry = ttk.Entry(self.frame)
        self.name_entry_label = ttk.Label(self.frame, text='User name', anchor=tkinter.W, justify=tkinter.LEFT)
        self.name_entry = ttk.Entry(self.frame)
        self.pwd_entry_label = ttk.Label(self.frame, text='Password', anchor=tkinter.W, justify=tkinter.LEFT)
        self.pwd_entry = ttk.Entry(self.frame, show='*')

        # Attempt a Log in.
        self.launch_button = ttk.Button(self.frame, text='Log In', command=self.launch_client)

        # Positioning the labels and text boxes appropriately
        # self.host_entry_label.grid(row = 0, column = 0, pady = 10, padx = 5)
        # self.host_entry.grid(row = 0, column = 1, pady = 10, padx = 5)
        # self.port_entry_label.grid(row = 1, column = 0, pady = 10, padx = 5)
        # self.port_entry.grid(row = 1, column = 1, pady = 10, padx = 5)
        self.name_entry_label.grid(row=2, column=0, pady=10, padx=5)
        self.name_entry.grid(row=2, column=1, pady=10, padx=5)
        self.pwd_entry_label.grid(row=3, column=0, pady=10, padx=5)
        self.pwd_entry.grid(row=3, column=1, pady=10, padx=5)
        self.launch_button.grid(row=5, column=1, pady=10, padx=5)

        # self.host_entry.focus_set()

        self.frame.pack(fill=tkinter.BOTH, expand=True)

    # Main Chat window
    def launch_client(self):

        # #Obtaining the host address and port number
        # self.host = self.host_entry.get()
        # self.port = self.port_entry.get()
        # self.port = int(self.port)
        self.host = "127.0.0.1"  # Hardcoded IP address
        self.port = 8000
        self.name = self.name_entry.get()
        self.pwd = self.pwd_entry.get()
        print(self.host, self.port)

        # Destroying the previous labels and entries
        # self.host_entry_label.destroy()
        # self.host_entry.destroy()
        # self.port_entry_label.destroy()
        # self.port_entry.destroy()
        self.name_entry_label.destroy()
        self.name_entry.destroy()
        self.pwd_entry_label.destroy()
        self.pwd_entry.destroy()

        self.launch_button.destroy()
        self.frame.pack_forget()

        # creating socket for client
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.settimeout(2);
        f = 0
        try:
            f = self.conn.connect((self.host, self.port))  # Attempting to connect to the server
        except:
            self.client_menu()
            return 0

        self.list_of_active_users = self.initial_setup()  # Obtaining the list of active users on successful connection to the user
        if self.list_of_active_users == -1:
            return 0
        self.flag = 0

        # MAIN WINDOW
        self.title('Yet Another Signal Clone')  # Window title
        self.should_quit = False
        self.protocol('WM_DELETE_WINDOW', self.client_quit)

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

        # #MENU BAR
        # top=self.winfo_toplevel()
        # self.menubar = tkinter.Menu(top,font=tkinter.font.Font(size=11,weight=tkinter.font.BOLD))
        # top['menu']=self.menubar
        # self.filemenu=tkinter.Menu(self.menubar,tearoff=0)                            #FILE MENU
        # self.filemenu.add_command(label="Save Chat",command=self.save_history)
        # self.filemenu.add_separator()
        # self.filemenu.add_command(label="Exit",command=self.client_quit)
        # self.menubar.add_cascade(label="File",menu=self.filemenu)
        # self.contact= tkinter.Menu(self.menubar,tearoff=0)                            #CONTACT MENU
        # self.contact.add_command(label="Add Contact",command=self.add_contact)
        # self.contact.add_command(label="Delete Contact",command=self.del_contact)
        # self.menubar.add_cascade(label="Contact",menu=self.contact)
        # self.chat=tkinter.Menu(self.menubar,tearoff=0)                                #CHAT MENU
        # self.enable = dict();self.checks=[]
        # self.chat.add_command(label="Select Chatters",command=self.user_selection)
        # self.menubar.add_cascade(label="Chat",menu=self.chat)

        # TEXT CHAT WINDOW
        self.chat_text = tkinter.Text(self.chat_frame, state=tkinter.DISABLED)
        self.scroll = tkinter.Scrollbar(self.chat_frame)  # Adding Scroll Bar to chat window
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
        self.send_button = ttk.Button(self.button_frame, image=self.img)  # Button for sending text message
        self.browsebutton = ttk.Button(self.button_frame, image=self.img1,
                                       command=self.browse)  # Button for browsing multimedia
        self.send_button.bind('<Button-1>', self.send)  # press button-1 to send messages
        self.chat_entry.bind('<Return>', self.send)  # Alternate to sending messages, hitting the return button

        # CLIENT FRAME
        self.user_icon = ttk.Label(self.clients_frame, image=self.img2, background='light blue', text=self.name,
                                   compound="top", font=self.font3, anchor=tkinter.E)  # Code for the Display Icon
        self.frame.pack(side=tkinter.TOP, fill=tkinter.BOTH,
                        expand=True)  # Packing the above created objects and giving them positions while packing
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
        # self.f1=ttk.Frame(self.clients_frame,style="new.TFrame")
        self.f2 = ttk.Frame(self.clients_frame, style="new1.TFrame")
        # self.tabs.add(self.f1,text="Online Users")
        self.tabs.add(self.f2, text="Contacts")
        # ONLINE USERS#
        # self.online=[];j=0
        # for i in self.list_of_active_users:
        #     # print(i)
        #     self.enable[i]=tkinter.IntVar()
        #     # self.enable[i].set(0)
        #     l=ttk.Label(self.f1,padding=10,text=i,justify=tkinter.LEFT,font=self.font3,foreground='forest green',background='navajo white')
        #     l.grid(row=j,column=0,sticky=tkinter.W)
        #     self.online.append(l)
        #     j=j+1
        # CONTACTS#
        self.contact_label = [];
        with open('textfiles/contact.txt', 'rb') as file:
            contacts = (file.read()).decode()
        self.contacts = contacts.split(' ')
        j = 0
        if "" in self.contacts:
            self.contacts.remove("")
            # Create a tkinter variable to hold the selected contact
            self.selected_contact = tkinter.StringVar()

            # Create a Combobox to display the contacts
            self.contact_combobox = ttk.Combobox(self.f2, textvariable=self.selected_contact, font=self.font3,
                                                 foreground='gray49', background='old lace')
            self.contact_combobox.grid(row=0, column=0, sticky=tkinter.W)
            self.contact_combobox['values'] = self.contacts
            # Bind a callback function to handle selection changes
            self.contact_combobox.bind("<<ComboboxSelected>>", self.handle_contact_selection)
            self.num_contacts = len(self.contacts)

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
                                                  target=self.clientchat)  # for client we will intiate a thread to display chat
        self.clientchat_thread.start()
        # self.clientchat_thread.join()

    def handle_contact_selection(self, event):
        selected_contact = self.selected_contact.get()
        print("Selected contact:", selected_contact)

    # RECEIVER SELECTION WINDOW
    def user_selection(self):
        self.root = tkinter.Toplevel(self)
        self.root.title("User Selection")
        frame = tkinter.Frame(self.root)
        frame1 = tkinter.Frame(frame)
        label1 = tkinter.Label(frame1, text="Select the users you want to connect to:", compound=tkinter.LEFT,
                               font=('Helvetica', '20'), justify=tkinter.CENTER)
        label1.pack(side=tkinter.TOP, fill=tkinter.X)  # LABEL at the top
        frame1.pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=True)
        frame2 = tkinter.Frame(self.root, borderwidth=10)
        i = 0
        for client in self.list_of_active_users:
            ch = tkinter.Checkbutton(frame2, text=client, variable=self.enable[client], borderwidth=0, pady=10,
                                     justify=tkinter.LEFT, font=('Courier New', 19), foreground='gray30')
            ch.grid(column=0, row=i, sticky=tkinter.W)
            i = i + 1
        frame3 = tkinter.Frame(frame2, borderwidth=10)
        b = tkinter.Button(frame3, text="Connect", justify=tkinter.CENTER, font=("Helvetica", '14'), padx=6, pady=6,
                           command=self.root.withdraw)
        b.pack()  # Button for connection and exiting this window
        frame3.grid(row=i, column=1, columnspan=2, sticky=tkinter.S)
        frame2.pack(side=tkinter.BOTTOM, fill=tkinter.BOTH, expand=True)
        frame.pack(fill=tkinter.BOTH, expand=True)

    # CONTACT ADDITION WINDOW
    def add_contact(self):
        self.root = tkinter.Toplevel(self)
        self.root.title("Contact Addition")
        label1 = tkinter.Label(self.root, text="Enter the Contact Details:", font=('Helvetica', 20),
                               justify=tkinter.CENTER, pady=10)
        label1.grid(row=0, columnspan=2)
        label2 = tkinter.Label(self.root, text="Username", font=("Courier New", 14), justify=tkinter.RIGHT, pady=15)
        label2.grid(row=1, column=0)
        self.contact = tkinter.StringVar()
        self.contact.set("Type Username")
        entry1 = tkinter.Entry(self.root, textvariable=self.contact)
        entry1.grid(row=1, column=1)
        entry1.bind("<Return>", self.add)

    def add(self, event):
        if self.contact.get() in self.contacts:
            tkinter.messagebox.showwarning(title="Contact Exists", message="The Contact already exists")
            self.root.withdraw()
        with open("textfiles/contact.txt", "a") as file:
            file.write(" " + self.contact.get())
        l = ttk.Label(self.f2, padding=10, text=self.contact.get(), justify=tkinter.LEFT, font=self.font3,
                      foreground='gray49',
                      background='ivory2')  # l.grid(row=self.num_contacts,column=0,sticky=tkinter.W)
        l.grid(row=self.num_contacts, column=0, sticky=tkinter.W)
        self.contact_label.append(l)
        self.contacts.append(self.contact.get())
        self.num_contacts += 1
        self.root.withdraw()

    # CONTACT DELETION WINDOW
    def del_contact(self):
        self.root = tkinter.Toplevel(self)
        self.root.title("Contact Deletion")
        label1 = tkinter.Label(self.root, text="Enter the Contact to be removed:", font=('Helvetica', 20),
                               justify=tkinter.CENTER, pady=10)
        label1.grid(row=0, columnspan=2, column=0)
        label2 = tkinter.Label(self.root, text="Username", font=("Courier New", 14), justify=tkinter.LEFT, pady=15)
        label2.grid(row=1, column=0)
        self.remove1 = tkinter.StringVar()
        self.remove1.set("Type Username")
        entry1 = tkinter.Entry(self.root, textvariable=self.remove1)
        entry1.grid(row=1, column=1)
        entry1.bind("<Return>", self.remove)

    def remove(self, event):
        # print(self.contacts,self.remove1.get())
        try:
            self.contacts.remove(self.remove1.get())
        except:
            tkinter.messagebox.showwarning(title="No Contact", message="No such contact exists")
            self.root.withdraw()
            return
        for i in self.contact_label:
            i.destroy()
        self.contact_label.clear()
        j = 0
        for i in self.contacts:
            l = ttk.Label(self.f2, padding=10, text=i, justify=tkinter.LEFT, font=self.font3, foreground='gray49',
                          background='ivory2')
            l.grid(row=j, column=0, sticky=tkinter.W)
            self.contact_label.append(l)
            j = j + 1
        self.num_contacts = j
        remove2 = ' '.join(self.contacts)
        with open('textfiles/contact.txt', 'wb') as file:
            file.write(remove2.encode())
        self.root.withdraw()

    # Save History Menu
    def save_history(self):
        self.save_file = tkinter.filedialog.asksaveasfilename(title="Choose save location",
                                                              filetypes=[('Plain text', '*.txt'), ('Any File', '*.*')])
        try:
            filehandle = open(self.save_file, "a")
        except:
            print("Can't save History")
            return
        contents = self.chat_text.get(1.0, tkinter.END);
        filehandle.write("Last Saved " + time.asctime(time.localtime(time.time())) + '\n')
        for line in contents:
            filehandle.write(line)
        filehandle.close()

    # Helper Function for sending messages
    def browse(self):
        if not self.list_of_active_users:
            tkinter.messagebox.showwarning(title="No Connection", message="Connect To Some User")
        else:
            self.mmfilename = tkinter.filedialog.askopenfilename()
            self.multimedia_send()

    def send(self, event):
        message = self.chat_entry.get()

        data = ""
        for client in self.list_of_active_users:
            if self.enable[client].get() == 1:
                data = data + "@" + client + ' '
        if data == "":
            tkinter.messagebox.showwarning(title="No Connection", message="Connect To Some User")
            return
        data = data + ':'
        data = data + message

        self.chat_entry.delete(0, tkinter.END)  # Emptying chat entry box

        self.conn.send(data.encode())  # Sending the encoded data to the server

        self.chat_text.config(state=tkinter.NORMAL)
        self.chat_text.insert(tkinter.END, self.name + ':' + message + '\n', ('tag{0}'.format(1)))
        self.chat_text.tag_config('tag{0}'.format(1), justify=tkinter.RIGHT, foreground='RoyalBlue3',
                                  font=self.chat_font)
        self.chat_text.config(
            state=tkinter.DISABLED)  # Again Disabling the edit functionality so that the user cannot edit it
        self.chat_text.see(tkinter.END)  # Enables the user to see the edited chat chat

    def multimedia_send(self):
        filename = self.mmfilename

        with open(filename, "rb") as file:
            encoded_string = (base64.b64encode(file.read())).decode()

        data = "^"
        for client in self.list_of_active_users:
            if self.enable[client].get() == 1:
                data = data + "@" + client + ' '

        data = data + ':'
        data = data + filename + ':'
        data_to_send = data + encoded_string

        # data_to_display = '^@'+dest+':'+ filename
        # data_to_send = data_to_display + ':' + encoded_string

        self.chat_entry.delete(0, tkinter.END)  # Emptying the chat entry box
        self.conn.send(data_to_send.encode())

        self.chat_text.config(state=tkinter.NORMAL)
        self.chat_text.insert(tkinter.END, self.name + ':' + filename + '\n', ('tag{0}'.format(1)))
        self.chat_text.tag_config('tag{0}'.format(1), justify=tkinter.RIGHT, foreground='RoyalBlue3',
                                  font=self.chat_font)
        self.chat_text.config(
            state=tkinter.DISABLED)  # Again Disabling the edit functionality so that the user cannot edit it
        self.chat_text.see(tkinter.END)  # Enables the user to see the edited chat chat

    # Client Thread Target
    def clientchat(self):
        while not self.should_quit:  # If we are not in the 'quit' state then do :
            try:
                data = self.conn.recv(RECV_BUFFER)
                data = data.decode()
                data = data.rstrip()

                if len(data):
                    if data[0] == "!":  # A list of active users received
                        self.list_of_active_users = data[1:].split(' ')
                        self.list_of_active_users.remove(self.name)

                        for l in self.online:  # Here we update the list of online users visible on client tab
                            l.destroy()

                        j = 0
                        for client in self.list_of_active_users:
                            if client not in self.enable:
                                self.enable[client] = tkinter.IntVar()
                                il = ttk.Label(self.f1, padding=10, text=client, justify=tkinter.LEFT, font=self.font3,
                                               foreground='forest green', background='navajo white')
                                il.grid(row=j, column=0, sticky=tkinter.W)
                                self.online.append(il)
                                j = j + 1
                            else:
                                il = ttk.Label(self.f1, padding=10, text=client, justify=tkinter.LEFT, font=self.font3,
                                               foreground='forest green', background='navajo white')
                                il.grid(row=j, column=0, sticky=tkinter.W)
                                self.online.append(il)
                                j = j + 1

                    elif data[0] == "^":  # A multimedia message received
                        data_recvd = data.split(':')
                        sendername = data_recvd[0][2:]
                        filename_process = data_recvd[1].split('/')
                        filename = filename_process[len(filename_process) - 1]
                        print(sendername)
                        print(filename)
                        encoded_string = data_recvd[2]
                        decoded_string = base64.b64decode(encoded_string)

                        with open(filename, "wb") as file:  # Creating a file with the same name
                            file.write(decoded_string)  # as send by the user to store the stuff

                        print_data = sendername + ': ' + filename
                        self.chat_text.config(state=tkinter.NORMAL)
                        self.chat_text.insert(tkinter.END, print_data + '\n', ('tag{0}'.format(2)))
                        self.chat_text.tag_config('tag{0}'.format(2), justify=tkinter.LEFT, foreground='gray30',
                                                  font=self.chat_font)
                        self.chat_text.config(state=tkinter.DISABLED)
                        self.chat_text.see(tkinter.END)
                    else:
                        self.chat_text.config(state=tkinter.NORMAL)
                        self.chat_text.insert(tkinter.END, data[1:] + '\n', ('tag{0}'.format(2)))
                        self.chat_text.tag_config('tag{0}'.format(2), justify=tkinter.LEFT, foreground='gray30',
                                                  font=self.chat_font)
                        self.chat_text.config(state=tkinter.DISABLED)
                        self.chat_text.see(tkinter.END)
                else:
                    break
            except:
                continue

    # Helper function for first time communication with server
    def initial_setup(self):
        got_list = False  # First time communication with the server
        list_of_active_user = []
        list_active_user = ""

        try:
            self.conn.send('0'.encode())  # Sending 0 to indicate that it is a non-registration message
        except:
            self.conn.close()  # Closing the connection and giving an option to reattempt
            self.wp_error = ttk.Label(self.frame, text='Cannot Connect to Server', anchor=tkinter.CENTER,
                                      justify=tkinter.CENTER)
            self.try_again = ttk.Button(self.frame, text='Try again', command=self.client_menu)
            self.wp_error.grid(row=0, column=1, pady=10, padx=5)
            self.try_again.grid(row=0, column=1, pady=10, padx=5)
            self.frame.pack(fill=tkinter.BOTH, expand=True)

        while 1:
            if not got_list:
                try:
                    data = self.conn.recv(RECV_BUFFER)  # Obtaining the list of all the active users
                    data = data.decode('utf-8')
                    data = data.rstrip()
                except:
                    self.conn.close()
                    self.client_menu()

                if data == "What is your name?":  # Getting the first message from the server
                    try:
                        self.conn.send(
                            str.encode(self.name + ' ' + self.pwd))  # Sending the name and password to the server
                    except:

                        self.conn.close()
                        self.client_menu()
                    try:
                        list_active_user = self.conn.recv(
                            RECV_BUFFER).decode()  # this will be a string of name separated by spaces
                    except:
                        self.conn.close()
                        self.client_menu()
                    if list_active_user == 'authentication_error':  # Authentication error implies that user is either not registered-
                        # -or password is incorrect. Redirecting to the Client menu

                        self.wp_error = ttk.Label(self.frame, text='Authentication_Error', anchor=tkinter.CENTER,
                                                  justify=tkinter.CENTER)
                        self.try_again = ttk.Button(self.frame, text='Try again', command=self.client_menu)
                        self.wp_error.grid(row=0, column=1, pady=10, padx=5)
                        self.try_again.grid(row=1, column=1, pady=10, padx=5)
                        self.try_again_bool = True
                        self.frame.pack(fill=tkinter.BOTH, expand=True)
                        return -1
                    else:
                        list_of_active_user = list(
                            list_active_user[1:].split(' '))  # now it has all the names separately, its not a string
                        list_of_active_user.remove(self.name)
                        # print(list_of_active_user)
                        got_list = True
            else:
                return list_of_active_user

    # Helper function for quit option
    def client_quit(self):
        if tkinter.messagebox.askokcancel(title="Quit Window", message="Do you really want to quit?"):
            self.should_quit = True
            # self.conn.send("#!quit".encode())
            # print(self.conn.recv(RECV_BUFFER).decode('utf-8'))
            self.conn.shutdown(socket.SHUT_WR)
            self.clientchat_thread.join()
            self.conn.close()
            self.destroy()
        else:
            pass


# DRIVER
if __name__ == '__main__':
    app = Application()

    app.launch_app()  # Launching the app

