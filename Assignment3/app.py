# system imports
import socket
from threading import Thread
import pygubu
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox

# local import from "protocol.py"
from protocol import Protocol

# REQUEST SECURE CONNECTION MESSAGE FLAG
# APP.py will send this to other APP.py instances to let them know to start
# encrypting with the inti_shared key.
CAPTURE_INIT_TOKEN = "␟CAPTURE_TOKEN␟"

class Assignment3VPN:
    # Constructor
    def __init__(self, master=None):
        # Initializing UI
        self.builder = builder = pygubu.Builder()
        builder.add_from_file("UI.ui")

        # Getting references to UI elements
        self.mainwindow = builder.get_object('toplevel', master)
        self.hostNameEntry  = builder.get_object('ipEntry', self.mainwindow)
        self.connectButton  = builder.get_object('connectButton', self.mainwindow)
        self.secureButton  = builder.get_object('secureButton', self.mainwindow)
        self.clientRadioButton = builder.get_object('clientRadioButton', self.mainwindow)
        self.serverRadioButton = builder.get_object('serverRadioButton', self.mainwindow)
        self.ipEntry = builder.get_object('ipEntry', self.mainwindow)
        self.portEntry = builder.get_object('portEntry', self.mainwindow)
        self.secretEntry = builder.get_object('secretEntry', self.mainwindow)
        self.sendButton = builder.get_object('sendButton', self.mainwindow)
        self.logsText = builder.get_object('logsText', self.mainwindow)
        self.messagesText = builder.get_object('messagesText', self.mainwindow)

        # Getting bound variables
        self.mode = None
        self.hostName = None
        self.port = None
        self.sharedSecret = None
        self.textMessage = None
        builder.import_variables(self, ['mode', 'hostName', 'port', 'sharedSecret', 'textMessage'])
        builder.connect_callbacks(self)

        # Network socket and connection
        self.s = None
        self.conn = None
        self.addr = None

        # Server socket threads
        self.server_thread = Thread(target=self._AcceptConnections, daemon=True)
        self.receive_thread = Thread(target=self._ReceiveMessages, daemon=True)

        # Creating a protocol object
        self.prtcl = Protocol()
        # Note the Updated GUI key is caputred upon trying to connect


    # Distructor
    def __del__(self):
        # Closing the network socket
        if self.s is not None:
            self.s.close()

        # Killing the spawned threads
        if self.server_thread.is_alive():
            self.server_thread.terminate()
        if self.receive_thread.is_alive():
            self.receive_thread.terminate()


    # Handle client mode selection
    def ClientModeSelected(self):
        self.hostName.set("localhost")

    def _CaptureSharedSecret(self):
        self.sharedSecret = self.secretEntry.get()
        self.prtcl.SetSharedKey(self.sharedSecret)


    # Handle sever mode selection
    def ServerModeSelected(self):
        pass


    # Create a TCP connection between the client and the server
    def CreateConnection(self):
        # Change button states
        self._ChangeConnectionMode()

        # Create connection
        if self._CreateTCPConnection():
            if self.mode.get() == 0:
                # enable the secure and send buttons
                self.secureButton["state"] = "enable"
                self.sendButton["state"] = "enable"
        else:
            # Change button states
            self._ChangeConnectionMode(False)


    # Establish TCP connection/port
    def _CreateTCPConnection(self):
        if not self._ValidateConnectionInputs():
            return False

        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.mode.get() == 0:
                self._AppendLog("CONNECTION: Initiating client mode...")
                self.s.connect((self.hostName.get(), int(self.port.get())))
                self.conn = self.s
                self.receive_thread.start()
                self._AppendLog("CLIENT: Connection established successfully. You can now send/receive messages.")
            else:
                self._AppendLog("CONNECTION: Initiating server mode...")
                self.s.bind((self.hostName.get(), int(self.port.get())))
                self.s.listen(1)
                self.server_thread.start()
            return True
        except Exception as e:
            self._AppendLog("CONNECTION: connection failed: {}".format(str(e)))
            return False


    # Accepting connections in a separate thread
    def _AcceptConnections(self):
        try:
            # Accepting the connection
            self._AppendLog("SERVER: Waiting for connections...")
            self.conn, self.addr = self.s.accept()
            self._AppendLog("SERVER: Received connection from {}. You can now send/receive messages".format(self.addr))

            # Starting receiver thread
            self.receive_thread.start()

            # Enabling the secure and send buttons
            self.secureButton["state"] = "enable"
            self.sendButton["state"] = "enable"
        except Exception as e:
            self._AppendLog("SERVER: Accepting connection failed: {}".format(str(e)))
            return False


    # Receive data from the other party
    def _ReceiveMessages(self):
        while True:
            try:
                # Receiving all the data
                cipher_text_bytes = self.conn.recv(4096)
                cipher_text = cipher_text_bytes.decode("UTF-8")
                # Check if socket is still open
                if cipher_text == None or len(cipher_text) == 0:
                    self._AppendLog("RECEIVER_THREAD: Received empty message")
                    break

                # This means that the other app.py instance wants to start communication
                # Over the inital secret channel as per the protocol class
                if CAPTURE_INIT_TOKEN in cipher_text:
                    self._CaptureSharedSecret()

                # Decode message
                plain_text = ""
                try:
                    # Note THis will be a string
                    plain_text = self.prtcl.DecryptAndVerifyMessage(cipher_text)
                except Exception as e:
                    self._AppendLog(f"Error: recieving message {e}")
                # Checking if the received message is part of your protocol
                if self.prtcl.IsMessagePartOfProtocol(plain_text): #checks if newest msg is part of protocol
                    if Protocol.PING_PREFIX in plain_text:
                        # PING received
                        # Disabling the button to prevent repeated clicks
                        self.secureButton["state"] = "disabled"
                        # Processing the protocol message
                        pem_public_key = self.prtcl.ProcessReceivedProtocolMessage(plain_text)
                        # sending public key
                        self._SendMessage(pem_public_key)
                    elif Protocol.PONG_PREFIX in plain_text:
                        # PONG receivec
                        try:
                            done_msg = self.prtcl.ProcessReceivedProtocolMessage(plain_text)
                            self._SendMessage(done_msg)
                        except Exception as e:
                            self._AppendLog(f"Failed to connect: {e}")
                            self._SendMessage(f"Failed to connect: {e}")
                            break
                    elif Protocol.DONE_PREFIX in plain_text:
                        _ = self.prtcl.ProcessReceivedProtocolMessage(plain_text)
                        self._SendMessage("!! ENCRYPTED SESSION ESTABLISHED !!")
                        self._AppendLog("!! ENCRYPTED SESSION ESTABLISHED !!")
                    else:
                        self._AppendLog("[-] Unknown protocol message")
                else:
                    self._AppendMessage("Other: {}".format(plain_text))

            except Exception as e:
                self._AppendLog("RECEIVER_THREAD: Error receiving data: {}".format(str(e)))
                return False


    # Send data to the other party
    def _SendMessage(self, message):
        if not self.prtcl.ping_pong_done and not self.prtcl.IsMessagePartOfProtocol(message):
            self._AppendLog(f"[-] WARNING: Secure connection not set, sending unencrypted")
        elif not self.prtcl.IsMessagePartOfProtocol(message):
            self._AppendLog(f"[+] PRE ENCRYPT: plaintext:\n{message}")
        plain_text = message
        cipher_text = self.prtcl.EncryptAndProtectMessage(plain_text)
        if self.prtcl.ping_pong_done and not self.prtcl.IsMessagePartOfProtocol(message):
            self._AppendLog(f"[+] POST ENCRYPT: sending the ciphertext:\n {cipher_text}")
        self.conn.send(cipher_text.encode("UTF-8"))

    # Secure connection with mutual authentication and key establishment
    def SecureConnection(self):
        # get the shared secret
        self._CaptureSharedSecret()
        # Tell the other participant to capture the shared secret to read
        # Auth messages
        self.conn.send(CAPTURE_INIT_TOKEN.encode("UTF-8"))
        # disable the button to prevent repeated clicks
        self.secureButton["state"] = "disabled"
        init_message = self.prtcl.GetProtocolInitiationMessage()
        self._SendMessage(init_message)


    # Called when SendMessage button is clicked
    def SendMessage(self):
        text = self.textMessage.get()

        # Sanitize user inputs to disallow inputs that mirror auth protocol
        if self.prtcl.IsMessagePartOfProtocol(text) or CAPTURE_INIT_TOKEN in text:
            self._AppendLog("[-] MESSAGE NOT ALLOWED.")
            self._AppendMessage("You: {}".format(text))
            self.textMessage.set("")
            return

        if  text != "" and self.s is not None:
            try:
                self._SendMessage(text)
                self._AppendMessage("You: {}".format(text))
                self.textMessage.set("")
            except Exception as e:
                self._AppendLog("SENDING_MESSAGE: Error sending data: {}".format(str(e)))
        else:
            messagebox.showerror("Networking", "Either the message is empty or the connection is not established.")


    # Clear the logs window
    def ClearLogs(self):
        self.logsText.configure(state='normal')
        self.logsText.delete('1.0', tk.END)
        self.logsText.configure(state='disabled')


    # Append log to the logs view
    def _AppendLog(self, text):
        self.logsText.configure(state='normal')
        self.logsText.insert(tk.END, text + "\n\n")
        self.logsText.see(tk.END)
        self.logsText.configure(state='disabled')


    def _AppendMessage(self, text):
        self.messagesText.configure(state='normal')
        self.messagesText.insert(tk.END, text + "\n\n")
        self.messagesText.see(tk.END)
        self.messagesText.configure(state='disabled')


    # Enabling/disabling buttons based on the connection status
    def _ChangeConnectionMode(self, connecting=True):
        value = "disabled" if connecting else "enabled"

        # change mode changing
        self.clientRadioButton["state"] = value
        self.serverRadioButton["state"] = value

        # change inputs
        self.ipEntry["state"] = value
        self.portEntry["state"] = value
        self.secretEntry["state"] = value

        # changing button states
        self.connectButton["state"] = value


    # Verifying host name and port values
    def _ValidateConnectionInputs(self):
        if self.hostName.get() in ["", None]:
            messagebox.showerror("Validation", "Invalid host name.")
            return False

        try:
            port = int(self.port.get())
            if port < 1024 or port > 65535:
                messagebox.showerror("Validation", "Invalid port range.")
                return False
        except:
            messagebox.showerror("Validation", "Invalid port number.")
            return False

        return True


    # Main UI loop
    def run(self):
        self.mainwindow.mainloop()


# Main logic
if __name__ == '__main__':
    app = Assignment3VPN()
    app.run()
