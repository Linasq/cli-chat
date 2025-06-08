import time
import db
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Input
from textual.reactive import reactive

#TODO
# connect with db, add those users to list
class ContactList(VerticalScroll):
    def __init__(self) -> None:
        super().__init__()
        self.active_users = []
        self.logged_in = False

    def compose(self) -> ComposeResult:
        if self.logged_in:
            for name in self.active_users:
                yield Static(f"👤 {name}", classes="contact")
        else:
            yield Static(f"Please log in to see your contacts list", classes='contact')


    def show_contacts(self):
        self.logged_in = True
        self.refresh()


    def get_user(self):
        return self.active_user
    

    def set_user(self, name: list):
        self.active_user = name


class ChatDisplay(VerticalScroll):
    messages = reactive([])


    def remove_messages(self):
        how_many = len(self.messages)
        for _ in range (how_many):
            self.messages.pop()
        self.update_messages()


    def append_message(self, sender: str, content: str):
        self.messages.append(f"{sender}: {content}")
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
        self.cursor = 0
        self.logged_in = 0

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

        # check if good login - server action

        # db operations
        db.encrypt_db(f'db/{msg[1]}.sql', b'123') # for test purposes
        self.cursor = db.open_db(f'db/{msg[1]}.sql')
        names = db.get_names(self.cursor)
        self.contact_list.set_user(names)
        self.logged_in = 1


    # create / open chat
    def chat(self, message):
        self.input.value = ""
        if len(message) > 2:
            self.chat_display.remove_messages()
            self.chat_display.append_message('App', 'ERROR: try command "/chat user"')
        elif message[1]:
            # create requests to db, to get users and history of chat if there is any
            pass
        else:
            self.chat_display.remove_messages()
            self.chat_display.append_message('App', 'ERROR: Please provide user you want to speak with')


    def on_input_submitted(self, event: Input.Submitted) -> None:
        message = event.value.split(' ')

        #check if anything meaningful is written
        tosend = 0
        for msg in message:
            if len(msg):
                tosend = 1
                break

        # create / open chat with given user
        if message[0].lower() == '/chat':
            self.chat(message)
        # login to an existing account
        elif message[0].lower() == '/login':
            self.login(message)
        # register a new user
        elif message[0].lower() == '/register':
            pass
        # print message and send it to the choosen user
        elif tosend or message[0][0] != '/' :
            self.chat_display.append_message("Ty", ' '.join(message))
            self.input.value = ""
        # not recognized command
        else:
            self.chat_display.remove_messages()
            self.chat_display.append_message("App", 'Try one of the following commands:')
            self.chat_display.append_message("App", '/chat user - start a chat with user')
            self.chat_display.append_message("App", '/login login password - login to an existing account')
            self.chat_display.append_message("App", '/register login password - create a new account')
            self.chat_display.append_message("App", 'or just start talking with your friend, when you have already opened chat')
            self.input.value = ""


    # quit app, encrypt db, close connection
    def action_on_exit(self):
        time.sleep(3)
        self.exit()



if __name__ == "__main__":
    ChatClientApp().run()

