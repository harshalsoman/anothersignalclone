from socket import *										#Importing all from socket module
from _thread import *										#Importing all from low-level threading api of python 
import sys
import mysql.connector

def create_db_connection():
    connection = mysql.connector.connect(
        host='127.0.0.1',
        user='root',
        password='',
        database='cryptography_project'
    )
    print("dB connected")
    return connection

def register_user(username, password):
    conn = create_db_connection()
    cursor = conn.cursor()
    query = "INSERT INTO users (username, password) VALUES (%s, %s)"
    try:
        cursor.execute(query, (username, password))
        conn.commit()
        print("User registered successfully")
    except mysql.connector.Error as err:
        print("Failed to insert data into MySQL table: {}".format(err))
    finally:
        cursor.close()
        conn.close()


#A function to send the current active list to all on the event of a except.
def send_active_list(sock):		
	active_list="!"				#The first letter of the active list is a '!' for telling the client side that this is an active list being sent
	for socket in SOCK_LIST:
		if socket != sock:
			active_list = active_list+SOCK_LIST[socket] + " "
	broadcast_data(sock, active_list)

#Helper function for each client connected through socket
def clientthread(conn,addr): 							
	try:
		type_msg = conn.recv(RECV_BUFFER) 				#initital msg type to distinguish between non registration and registration messages
		type_msg = type_msg.decode()  					#to convert encoded received msg to string
	except:
		conn.close()
		sys.exit()		

	if type_msg =='0': 								    #If initial message is '0' then, non reg msg
		
		first_time = True         #When msg sent for first time after connection,- 
							      #-name and pwd req for authentication, this maintains the state
		name_enter = False

		#infinite loop to handle a single client thread
		while True:
			#Sending first message to connected client
			if first_time == True:
				instr = 'What is your name?'
				conn.send(instr.encode()) 
				first_time = False
				name_enter = True
			else:
				if name_enter:
					name_pwd = conn.recv(RECV_BUFFER) #Receiving name and password from the client for authentication
					name_pwd = name_pwd.decode() 
					name_pwd = name_pwd.rstrip().split(' ') #The msg format : <name> <password>. This processes it to return a list 
					name = name_pwd[0]						#this is the name of the newly connected client
					pwd = name_pwd[1]						#this is the password of the newly connected client

					if authenticate(name,pwd): #Authenticating the new user(i.e. whether username and password are present in local database)
						USERS_LIST[name]=conn 	#Maps the name to the socket
						SOCK_LIST[conn]=name  	#Maps the socket to the name
						print(name+" logged in")
						name_enter = False
						
						active_list="!"		#List of active users initialized with "!"
						for socket in SOCK_LIST:
							if socket != conn:
								active_list = active_list+SOCK_LIST[socket] + " "	#Adding to the active list names of all active users (represented by SOCK_LIST[socket])
						try:
							active_list = active_list + name  #The name of the client itself should be at the end
							conn.send(active_list.encode()) #Sending the active list to the just logged in client
							broadcast_data(conn,active_list) #Sending the active list to all other clients
						except:									#Usual Error Handling
							conn.close()							#If there's any error encountered, then:
							send_active_list(conn)							
							del(USERS_LIST[SOCK_LIST[conn]])		#Remove the name from the USERS_LIST
							del(SOCK_LIST[conn])					#Remove the socket from the SOCK_LIST
							sys.exit()								#Exit , i.e. end the thread for this client socket
					else:
						conn.send('authentication_error'.encode())	#If authentication fails, i.e user-password not found, then 
						conn.close() 	#close the socket
						sys.exit()

				else:			#If authentication done, then normal chatting, do this:
					try:
						data = conn.recv(RECV_BUFFER) #Receiving the data in encoded form from the client
						data = data.decode()	#Decoding the received data to string
					except:					#Usual Error Handling
						conn.close()
						send_active_list(conn)
						del(USERS_LIST[SOCK_LIST[conn]])
						del(SOCK_LIST[conn])
						sys.exit()

					#if client wants to disconnect 
					if data == "#!quit":
						conn.send('Connection shutting down with server\n'.encode())
						print("  %s went offline" % SOCK_LIST[conn])
						conn.close() 				#usual steps to end the connection
						send_active_list(conn)
						del(USERS_LIST[SOCK_LIST[conn]])
						del(SOCK_LIST[conn])
						sys.exit()
					elif data.startswith("!addcontact"):
						contact_name = data.split(':')[1]
						if contact_name in USERS_LIST:  # Assuming USERS_LIST is a dictionary of username to socket mappings
							target_conn = USERS_LIST[contact_name]
							message = f"!notifycontact:{addr[0]} wants to add you as a contact"
							target_conn.send(message.encode())
					else:
						#handling the messages received from a client 
						try:
							if data[0] != '@' and data[0] != '^':	#If this msg does not start with @ or ^ , then it is broadcast
								broadcast_data(conn, "\r" + SOCK_LIST[conn] + ': ' + data)
							elif data[0] == '^':
								temp = data.split(':')
								temp2 = temp[0][2:].split('@')
								list_of_names = list(map(lambda x: x.rstrip(), temp2))
								list_of_socks = list(map(lambda x : USERS_LIST[x], list_of_names))
								multicast_data(conn,list_of_socks,"\r" + SOCK_LIST[conn] + ':' + ':'.join(temp[1:]),True)
							else:				#Processing a multicast msg
								temp = data.split(':') #format: @<user1> @<user2>... : <msg>
								temp2 = temp[0][1:].split('@')
								list_of_names = list(map(lambda x: x.rstrip(), temp2))
								list_of_socks = list(map(lambda x : USERS_LIST[x], list_of_names))
								multicast_data(conn, list_of_socks, "\r" + SOCK_LIST[conn] + ':' + ':'.join(temp[1:]),False)
														
						except:
							print ("  %s went offline" % SOCK_LIST[conn])
							conn.close() #Usual closing
							send_active_list(conn)
							del(USERS_LIST[SOCK_LIST[conn]])
							del(SOCK_LIST[conn])
							sys.exit()
	else:
		#handling a registration request
		name_pwd = list(type_msg.rstrip().split(' '))
		name = name_pwd[0]
		pwd = name_pwd[1]
		reg_user(name, pwd)
		conn.close()
		sys.exit()


#helper function for authentication
def authenticate(username, password):
    conn = create_db_connection()
    cursor = conn.cursor()
    query = "SELECT password FROM users WHERE username = %s"
    try:
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        if result:
            stored_password = result[0]
            # Directly compare the provided password with the one stored in the database
            if password == stored_password:
                print("Login successful")
                return True
            else:
                print("Invalid password")
        else:
            print("Username not found")
    except mysql.connector.Error as err:
        print("Error querying the database: {}".format(err))
    finally:
        cursor.close()
        conn.close()
    return False

#helper function for registering a user
def reg_user(uname,pwd):
	register_user(uname, pwd)

#helper function for broadcasting a message
def broadcast_data (sock, message):
	for socket in SOCK_LIST:
		if  socket != sock:					#Avoiding broadcast to the user who send the message
			try :
				socket.send(message.encode())
			except :
				socket.close()				#Usual error hadling
				send_active_list(socket)
				del(USERS_LIST[SOCK_LIST[socket]])
				del(SOCK_LIST[socket])

#helper function for sending message to multiple users
def multicast_data(sock, list_of_sock,message,multimedia):
	for socket in list_of_sock:				#list_of_sock is the list of intended receivers
		if socket in SOCK_LIST:
			try:
				if multimedia:
					data = '^'+ message
					socket.send(data.encode())
				else:
					socket.send(message.encode())
			except:
				socket.close()				#Usual error handling
				send_active_list(socket)
				del(USERS_LIST[SOCK_LIST[socket]])
				del(SOCK_LIST[socket])
		elif socket != sock:
			try:
				sock.send("oops USER NOT PRESENT!\n".encode()) 
			except: 						#usual error handling
				sock.close()
				send_active_list(socket)
				del(USERS_LIST[SOCK_LIST[sock]])
				del(SOCK_LIST[sock])
				sys.exit()	

#DRIVER
if __name__ == "__main__":

	if(len(sys.argv) < 2):
		print ('Usage : python3 server.py port')
		sys.exit()

	sock = socket(AF_INET,SOCK_STREAM)                #Creating socket object
	
	host ='127.0.0.1'                                 # Defining server address and port
	port = int(sys.argv[1]) 						  #Warning: Never use ports<1024 as they are used for internal networking
	
	sock.bind((host, port))                           #Binding socket to a address. bind() takes tuple of host and port.
	
	sock.listen(50)                                   #Listening at the address
													  #50 denotes the number of clients can queue

	RECV_BUFFER = 10000000 						

	USERS_LIST = dict() #A map of all active users' names to sockets
	SOCK_LIST = dict()	#A map of all active users' sockets to names
	dbConn = create_db_connection()
	print(dbConn)
 
	print ("Chat server started on port " + str(port) + " and the IP address is " + str(host))
 
	while True:
		conn, addr = sock.accept()					  #Accepting incoming connections
		if (conn):
			print("Connected")
		
		start_new_thread(clientthread,(conn,addr))    #Creating new thread for handling each client using low-level threading api
 
sock.close() #close socket after all is done
