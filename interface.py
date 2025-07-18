import network_backend as net
import crypto_functions as crypto
import db
import time
from datetime import datetime
import json
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Input
from textual.reactive import reactive

'''
TODO
- dodac szyfrowanie
'''

def get_time():
    date_now = datetime.now()
    date_str = datetime.strftime(date_now, '\[%H:%M, %d.%m]')
    return date_str


class ContactList(VerticalScroll):
    def __init__(self) -> None:
        super().__init__()
        self.contacts = ()
        self.logged_in = False


    def compose(self) -> ComposeResult:
        yield Static(f"Please log in to see your contacts list", classes='contact')


    def update_contacts(self):
        self.remove_children()
        if self.logged_in:
            for name in self.contacts:
                self.mount(Static(f"👤 {name}", classes="contact"))
        else:
            self.mount(Static(f"Please log in to see your contacts list", classes='contact'))


    def get_contact(self):
        return self.contacts
    

    def set_contact(self, name: list):
        self.contacts = [i for ii in name for i in ii]
        self.logged_in = True
        self.update_contacts()


    def set_login(self):
        self.logged_in = not self.logged_in


class ChatDisplay(VerticalScroll):
    messages = reactive([])


    def remove_messages(self):
        '''
        Removes all messages from screen
        '''
        how_many = len(self.messages)
        for _ in range (how_many):
            self.messages.pop()
        self.update_messages(False)


    def append_message(self, sender: str, content: str, date=None, recv=False):
        '''
        Prints message to the screen, has several additional options
        '''
        prefix = f'[{date}]' if date else ''
        self.messages.append(f"{prefix} {sender}: {content}")
        self.update_messages(recv)
        return


    def update_messages(self, recv: bool):
        self.remove_children()
        for msg in self.messages:
            if recv:
                self.call_later(self.mount, Static(msg, classes="message"))
            else:
                self.mount(Static(msg, classes="message"))
        return


class ChatClientApp(App):
    BINDINGS = [("ctrl+q", "on_exit", "Quit the app")]
    CSS = """
    Screen {
        layout: vertical;
    }

    .main {
        layout: horizontal;
        height: 1fr;
    }

    ContactList {
        width: 25%;
        border: wide $secondary;
    }

    ChatDisplay {
        width: 75%;
        border: wide $primary;
        padding: 1 1;
    }

    Input {
        dock: bottom;
        border: heavy $accent;
        height: 3;
    }

    .contact {
        padding: 1 1;
    }

    .message {
        padding: 0 1;
    }
    """


    def __init__(self):
        super().__init__()
        # self.cursor = 0
        self.logged_in = 0
        self.active_user = ''
        self.group = []
        self.username = ''
        self.error_msg = ''
        self.db_name = ''
        self.my_keys = {}
        self.EK_msg = ''
        self.EK_key = {}
        self.active_user_keys = {}
        self.SK = ''
        self.md5_hash = ''


    def compose(self) -> ComposeResult:
        self.chat_display = ChatDisplay()
        self.contact_list = ContactList()
        self.input = Input(placeholder="Wpisz wiadomość i naciśnij Enter...")

        yield Container(
            Horizontal(
                self.contact_list,
                self.chat_display,
                classes="main"
            ),
            self.input
        )

    
    def login(self, msg: list[str]):
        '''
        It saves username and hashes password. It then constructs payload that is sent to server.
        After few seconds it should get response back, which will determine next process.

        If login went smoothly, it decrypts DB, get contacts and updates them.
        Also it sets up login state and prints welcome message
        '''
        if len(msg) != 3:
            self.chat_display.remove_messages()
            self.chat_display.append_message('App', 'ERROR: try command "/login user password"')
            return

        self.username = db.sanitize_input(msg[1])
        hash = crypto.hash_md5(msg[2].encode())

        '''
        a,_= crypto.generate_keys_to_send(self.username)
        key = bytes.fromhex(a['IK_dh_pub'])
        with open('key', 'wb') as f:
            f.write(key)
        '''

        payload = {'type':'login', 'username':self.username, 'password':hash}
        self.client.send_message(json.dumps(payload).encode())

        if self.client.event.wait(1):
            self.chat_display.append_message('App', 'ERROR: sent message to server but no response received')
            return

        if self.error_msg != 'OK':
            self.chat_display.append_message('App', self.error_msg)
            return

        # db operations
        # TODO
        # get key to decrypt db
        self.db_name = f'db/{self.username}.db'
        # db.open_db(self.db_name)
        # db.decrypt_db(self.db_name, key) # for test purposes
        names = db.get_names(self.db_name)
        self.contact_list.set_login()
        self.contact_list.set_contact(names)
        self.logged_in = 1

        # notification on chat
        self.chat_display.remove_messages()
        self.chat_display.append_message('App', f'Welcome back: {self.username}')
        self.chat_display.append_message('App', 'Successfully logged in')
        self.chat_display.append_message('App', 'Now you can chat with others!!')
        self.chat_display.append_message('App', '/chat username')
        return

    # TODO check if user we want to connect with is registerd
    # create / open chat
    def chat(self, message: list[str]):
        '''
        It tries to create / open chat with given username
        If the user exist it then sanitizes username, sets it as active user
        and gets history from chat.

        If there is any history it prints it out and updates contact list
        '''
        if not self.logged_in:
            self.chat_display.remove_messages()
            self.chat_display.append_message('App', 'You are not logged in')
            return

        if len(message) > 2:
            self.chat_display.remove_messages()
            self.chat_display.append_message('App', 'ERROR: try command "/chat user" or "/chat group_name"')
        elif message[1]:
            user = db.sanitize_input(message[1])
            self.active_user = user
            '''
            payload = {
                    "type": "fetch_ephemeral",
                    "user_id": self.active_user
                    "initiator_id": self.username
                    }
            self.client.send_message(json.dumps(payload).encode())


            if self.client.event.wait(1):
                self.chat_display.append_message('App', 'ERROR: request for EK sent to server but no response received')

            elif self.EK_msg == "No ephemeral key found for user":
                payload = {
                        "type": "fetch_keys",
                        "user_id": self.active_user
                        }
                self.client.send_message(json.dumps(payload).encode())

                self.SK, self.md5_hash, ephemerals_to_send = crypto.establish_session_key_initiator(self.username, self.my_keys, self.active_user_keys)
                self.client.send_message(json.dumps(ephemerals_to_send).encode())

            else:
                payload = {
                    "type": "fetch_keys",
                    "user_id": self.active_user
                    }
                self.client.send_message(json.dumps(payload).encode())

                self.SK, self.md5_hash = crypto.establish_session_key_responder(self.my_keys, self.active_user_keys, self.EK_key)
            '''
            chat_history = db.get_history(self.db_name, self.active_user)
            self.chat_display.remove_messages()
            if chat_history:
                self.group = chat_history[0][3].split(',')
                for msg in chat_history:
                    self.chat_display.append_message(f'{msg[0]} {msg[1]}', f'{msg[2]}')
            names = db.get_names(self.db_name)
            self.contact_list.set_contact(names)
        else:
            self.chat_display.remove_messages()
            self.chat_display.append_message('App', 'ERROR: Please provide user you want to speak with')
        return


    def register(self, msg: list[str]):
        '''
        Tries to register user specified by username and password
        by sending a payload containing login and passwords hash
        to server.

        It prints out SUCCESS message on success
        '''
        if len(msg) != 3:
            self.chat_display.append_message('App', 'ERROR: wrong usage of command "/register". Try:')
            self.chat_display.append_message('App', '/register user password')
            return

        username = db.sanitize_input(msg[1])
        password = crypto.hash_md5(msg[2].encode())

        to_send = {'type':'register', 'login':username, 'password':password}

        self.client.send_message(json.dumps(to_send).encode())
        
        if self.client.event.wait(1):
            self.chat_display.append_message('App', 'ERROR: sent message to server but no response received')
            return

        if self.error_msg != 'OK':
            self.chat_display.append_message('App', self.error_msg)
            return
        '''
        payload, self.my_keys = crypto.generate_keys_to_send(username)
        self.client.send_message(json.dumps(payload).encode())
        '''
        # if there was nothing wrong
        self.chat_display.append_message('App', f'SUCCESS: Now you can log in to your account. Your username is: {username}')
        self.client.set_event()
        return 


    def add_group(self, msg: list[str]):
        '''
        Creates group "name" with usernames seperated by ","
        Checks if each user is registered
        Creates table with given name
        Inserts msg to db
        '''
        self.chat_display.remove_messages()
        self.active_user = ''

        if len(msg) != 3:
            self.chat_display.append_message('App', f'ERROR: wrong usage of command "/group". Try:')
            self.chat_display.append_message('App', f'/group group_name user1,user2,...')
            return

        if not self.logged_in:
            self.chat_display.append_message('App', f'ERROR: you are not logged in')
            return

        name = db.sanitize_input(msg[1])
        group = [db.sanitize_input(i) for i in msg[2].split(',')]
        if self.username not in group:
            group.append(self.username)

        for user in group:
            payload = {'type': 'is_registered', 'username':user}
            self.client.send_message(json.dumps(payload).encode())

            if self.client.event.wait(1):
                self.chat_display.append_message('App', 'ERROR: sent message to server but no response received')
                return

            if self.error_msg != 'OK':
                self.chat_display.append_message('App', self.error_msg)
                return

            self.client.set_event()

        # if everyone is registered
        db.get_history(self.db_name, name) # just creating table
        db.insert_chat(self.db_name, get_time(), name, 'APP', f'Successfully created group "{name}"', group) # add msg
        names = db.get_names(self.db_name) # update contact list
        self.contact_list.set_contact(names)
        return


    def recv_msg(self, data: bytes):
        '''
        Handles incoming messages 
        '''
        msg = json.loads(data)

        if msg['type'] in ['login', 'register', 'is_registered']:
            self.error_msg = msg['msg']
            self.client.set_event()
        elif msg['type'] in ['no_EK']:
            self.EK_msg = msg['msg']
        elif msg['type'] in ['EK_key']:
            self.EK_key = msg['msg']
        elif msg['type'] in ['user_keys']:
            self.active_user_keys = msg['msg']
        elif msg['type'] == 'msg':
            if not msg['name']:
                name = msg['src']
                db.get_history(self.db_name, name) # create table if not exists
                names = db.get_names(self.db_name)
                self.contact_list.set_contact(names)
            else:
                name = msg['name']
            db.insert_chat(self.db_name, get_time(), name, msg['src'], msg['msg'], [''])
            if self.active_user == name:
                self.chat_display.append_message(msg['src'], msg['msg'], None, True)


    def set_client(self, client: net.PersistentClient):
        '''
        Sets object net.PersistentClient
        Needed to network stuff
        '''
        self.client = client


    def on_input_submitted(self, event: Input.Submitted) -> None:
        '''
        Inputs from user are being processed by this function.
        
        First input is split to check the 1st word
        1st word specifies what function will handle message
        
        If there is nothing special in input, the input is send to choosen active user / group
        '''
        message = event.value.split(' ')
        self.input.value = ""
       
        # create / open chat with given user
        if message[0].lower() == '/chat':
            self.chat(message)
        # login to an existing account
        elif message[0].lower() == '/login':
            self.login(message)
        # register a new user
        elif message[0].lower() == '/register':
            self.register(message)
        # create group of users
        elif message[0].lower() == '/group':
            self.add_group(message)
        # exit from app
        elif message[0].lower() == '/exit' or message[0].lower() == ':q':
            self.action_on_exit()
        # not recognized command
        elif message[0] and message[0][0] == '/':
            self.chat_display.remove_messages()
            self.chat_display.append_message("App", 'Try one of the following commands:')
            self.chat_display.append_message("App", '/register login password - create a new account')
            self.chat_display.append_message("App", '/login login password - login to an existing account')
            self.chat_display.append_message("App", '/chat user - start a chat with user')
            self.chat_display.append_message("App", '/group group_name user1,user2,... - create group group_name with users seperated with coma')
            self.chat_display.append_message("App", '/exit or :q or ctrl+q to quit')
            self.chat_display.append_message("App", 'or just start talking with your friend, when you have already opened chat')
            self.input.value = ""
        # print message and send it to the choosen user
        else:
            if self.active_user:
                db.insert_chat(self.db_name, get_time(), self.active_user, 'Ty', ' '.join(message), self.group)
                if self.group != [""] and self.group:
                    dst = self.group
                    name = self.active_user
                else:
                    dst = self.active_user
                    name = ''
                payload = {'type':'msg', 'src':self.username, 'name':name, 'dst':dst, 'msg':' '.join(message)}
                self.client.send_message(json.dumps(payload).encode())
            else:
                self.chat_display.append_message("App", 'You have not choosen user to write to')
            self.chat_display.append_message("Ty", ' '.join(message))


    # quit app, encrypt db, close connection
    def action_on_exit(self):
        '''
        Callable function, that handles closing the app
        '''
        # TODO
        # encrypt db, close connection with server, exit
        try:
            '''
            with open('key', 'rb') as f:
                key = f.read()
            db.encrypt_db(f'db/{self.username}.db', key) # for test purposes
            '''
            self.client.close()
        except AttributeError:
            pass
        time.sleep(0.2)
        self.exit()



if __name__ == "__main__":
    ChatClientApp().run()

