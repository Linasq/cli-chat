from Crypto.Hash import MD5
import time
import db
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Input
from textual.reactive import reactive


class ContactList(VerticalScroll):
    def __init__(self) -> None:
        super().__init__()
        self.contacts = []
        self.logged_in = False


    def compose(self) -> ComposeResult:
        if self.logged_in:
            for name in self.contacts:
                yield Static(f"👤 {name}", classes="contact")
        else:
            yield Static(f"Please log in to see your contacts list", classes='contact')


    def show_contacts(self):
        self.logged_in = True
        self.refresh()


    def get_contact(self):
        return self.contacts
    

    def set_contact(self, name: list):
        self.contacts = name


    def set_login(self, is_logged: bool):
        self.logged_in = is_logged

class ChatDisplay(VerticalScroll):
    messages = reactive([])


    def remove_messages(self):
        how_many = len(self.messages)
        for _ in range (how_many):
            self.messages.pop()
        self.update_messages()


    def append_message(self, sender: str, content: str, date=None):
        if not date:
            self.messages.append(f"{sender}: {content}")
            self.update_messages()
        else:
            self.messages.append(f"[{date}] {sender}: {content}")
            self.update_messages()


    def update_messages(self):
        self.remove_children()
        for msg in self.messages:
            self.mount(Static(msg, classes="message"))


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
        self.input.value = ""
        if len(msg) != 3:
            self.chat_display.remove_messages()
            self.chat_display.append_message('App', 'ERROR: try command "/login user password"')
            return

        #TODO
        # check if good login - server action
        login = db.sanitize_input(msg[1])
        hash = MD5.new(msg[2].encode()) # create hash of passwd

        # db operations
        db.decrypt_db(f'db/{login}.db', b'123') # for test purposes
        self.cursor = db.open_db(f'db/{login}.db')
        names = db.get_names(self.cursor)
        self.contact_list.set_login(True)
        self.contact_list.set_contact(names)
        self.contact_list.show_contacts()
        self.logged_in = 1

        # notification on chat
        self.chat_display.remove_messages()
        self.chat_display.append_message('App', f'Welcome back: {login}')
        self.chat_display.append_message('App', 'Successfully logged in')
        self.chat_display.append_message('App', 'Now you can chat with others!!')
        self.chat_display.append_message('App', '/chat username')


    # create / open chat
    def chat(self, message: list[str]):
        self.input.value = ""
        if not self.logged_in:
            self.chat_display.remove_messages()
            self.chat_display.append_message('App', 'You are not logged in')
            return

        if len(message) > 2:
            self.chat_display.remove_messages()
            self.chat_display.append_message('App', 'ERROR: try command "/chat user"')
        elif message[1]:
            #TODO
            # create requests to db, to get users and history of chat if there is any
            user = db.sanitize_input(message[1])
            self.active_user = user
            chat_history = db.get_history(self.cursor, self.active_user)
            self.chat_display.remove_messages()
            self.chat_display.append_message('App', ';'.join(chat_history))
        else:
            self.chat_display.remove_messages()
            self.chat_display.append_message('App', 'ERROR: Please provide user you want to speak with')


    def on_input_submitted(self, event: Input.Submitted) -> None:
        message = event.value.split(' ')
       
        # create / open chat with given user
        if message[0].lower() == '/chat':
            self.chat(message)
        # login to an existing account
        elif message[0].lower() == '/login':
            self.login(message)
        # register a new user
        elif message[0].lower() == '/register':
            pass
        # not recognized command
        elif message[0] and message[0][0] == '/':
            self.chat_display.remove_messages()
            self.chat_display.append_message("App", 'Try one of the following commands:')
            self.chat_display.append_message("App", '/chat user - start a chat with user')
            self.chat_display.append_message("App", '/login login password - login to an existing account')
            self.chat_display.append_message("App", '/register login password - create a new account')
            self.chat_display.append_message("App", 'or just start talking with your friend, when you have already opened chat')
            self.input.value = ""
        # print message and send it to the choosen user
        else:
            #TODO
            # send over network
            db.insert_chat(self.cursor, self.active_user, 'Ty', ''.join(message), self.group)
            self.chat_display.append_message("Ty", ' '.join(message))
            self.input.value = ""


    # quit app, encrypt db, close connection
    def action_on_exit(self):
        time.sleep(3)
        self.exit()



if __name__ == "__main__":
    ChatClientApp().run()

