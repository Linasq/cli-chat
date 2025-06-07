import time
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Input
from textual.reactive import reactive

#TODO
# connect with db, add those users to list
class ContactList(VerticalScroll):
    active_user = ''

    def compose(self) -> ComposeResult:
        # Przykładowe kontakty
        for name in ["Anna", "Bartek", "Celina", "Damian", "Ela"]:
            yield Static(f"👤 {name}", classes="contact")


    def get_user(self):
        return self.active_user
    

    def set_user(self, name: str):
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

    def compose(self) -> ComposeResult:
        self.chat_display = ChatDisplay()
        self.input = Input(placeholder="Wpisz wiadomość i naciśnij Enter...")

        yield Container(
            Horizontal(
                ContactList(),
                self.chat_display,
                classes="main"
            ),
            self.input
        )


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
            self.chat_display.remove_messages()
            self.input.value = ""
        # login to an existing account
        elif message[0].lower() == '/login':
            pass
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

