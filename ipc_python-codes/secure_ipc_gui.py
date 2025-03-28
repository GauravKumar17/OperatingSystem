import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
from secure_ipc import SecureIPCServer, SecureIPCClient, SecureMessage

class SecureIPCApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure IPC GUI")
        
        self.server = None
        self.client = None
        
        self.init_ui()
    
    def init_ui(self):
        self.text_area = scrolledtext.ScrolledText(self.root, width=50, height=20)
        self.text_area.grid(row=0, column=0, columnspan=2)
        
        self.start_server_btn = tk.Button(self.root, text="Start Server", command=self.start_server)
        self.start_server_btn.grid(row=1, column=0)
        
        self.connect_client_btn = tk.Button(self.root, text="Connect Client", command=self.connect_client)
        self.connect_client_btn.grid(row=1, column=1)
        
        self.message_entry = tk.Entry(self.root, width=40)
        self.message_entry.grid(row=2, column=0)
        
        self.send_btn = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_btn.grid(row=2, column=1)
    
    def start_server(self):
        def run_server():
            self.server = SecureIPCServer(port=9000)
            self.server.register_handler("message", self.handle_message)
            self.server.start()
        
        threading.Thread(target=run_server, daemon=True).start()
        self.text_area.insert(tk.END, "Server started on port 9000\n")
    
    def connect_client(self):
        self.client = SecureIPCClient(server_port=9000)
        self.client.register_handler("message", self.receive_message)
        if self.client.connect():
            self.text_area.insert(tk.END, "Client connected to server\n")
        else:
            messagebox.showerror("Error", "Failed to connect to server")
    
    def send_message(self):
        if self.client:
            text = self.message_entry.get()
            self.client.send_message("message", {"text": text})
            self.text_area.insert(tk.END, f"Sent: {text}\n")
        else:
            messagebox.showerror("Error", "Client not connected")
    
    def handle_message(self, message):
        response = SecureMessage(
            sender_id=self.server.server_id,
            recipient_id=message.sender_id,
            message_type="message",
            payload={"text": f"Echo: {message.payload.get('text', '')}"}
        )
        return response
    
    def receive_message(self, message):
        self.text_area.insert(tk.END, f"Received: {message.payload.get('text', '')}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureIPCApp(root)
    root.mainloop()
