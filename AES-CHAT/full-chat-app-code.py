import customtkinter as ctk
import threading
import socket
import os
from ctr import AES
from datetime import datetime
import time

class EncryptedMessageDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Live Encryption View")
        self.geometry("600x400")
        
        # Make the window stay on top
        self.attributes('-topmost', True)
        
        # Original message section
        original_label = ctk.CTkLabel(self, text="Original Message:")
        original_label.pack(pady=(20, 5))

        self.original_box = ctk.CTkTextbox(self, height=80, width=560, wrap="word")
        self.original_box.pack(pady=(0, 20), padx=20)
        self.original_box.configure(state="disabled")

        # Encrypted message section
        encrypted_label = ctk.CTkLabel(self, text="Encrypted Message (hex):")
        encrypted_label.pack(pady=5)

        self.encrypted_box = ctk.CTkTextbox(self, height=160, width=560, wrap="word")
        self.encrypted_box.pack(pady=(0, 20), padx=20)
        self.encrypted_box.configure(state="disabled")
        
        # Status label for timestamps
        self.status_label = ctk.CTkLabel(
            self,
            text="Waiting for messages...",
            font=("Arial", 10),
            text_color="#888888"
        )
        self.status_label.pack(pady=10)

    def update_content(self, original_message, encrypted_message):
        # Update original message
        self.original_box.configure(state="normal")
        self.original_box.delete("1.0", "end")
        self.original_box.insert("1.0", original_message)
        self.original_box.configure(state="disabled")
        
        # Update encrypted message
        self.encrypted_box.configure(state="normal")
        self.encrypted_box.delete("1.0", "end")
        self.encrypted_box.insert("1.0", encrypted_message.hex())
        self.encrypted_box.configure(state="disabled")
        
        # Update timestamp
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_label.configure(text=f"Last update: {timestamp}")

class ChatGUI:
    def __init__(self):
        self.window = ctk.CTk()
        self.window.title("Secure Chat")
        self.window.geometry("800x600")
        
        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.create_login_frame()
        self.create_chat_frame()
        
        # Initially show login frame
        self.login_frame.pack(expand=True, fill="both", padx=20, pady=20)
        self.chat_frame.pack_forget()
        
        self.is_connected = False
        self.client = None
        self.aes = None
        self.animation_label = None
        self.animation_thread = None
        self.encryption_window = None

    def create_login_frame(self):
        self.login_frame = ctk.CTkFrame(self.window)
        
        # Title
        title = ctk.CTkLabel(
            self.login_frame, 
            text="Secure Chat Login",
            font=("Arial", 24, "bold")
        )
        title.pack(pady=20)
        
        # Server details
        server_frame = ctk.CTkFrame(self.login_frame)
        server_frame.pack(fill="x", padx=20, pady=10)
        
        self.host_entry = ctk.CTkEntry(
            server_frame,
            placeholder_text="Server Host"
        )
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.pack(side="left", expand=True, padx=5)
        
        self.port_entry = ctk.CTkEntry(
            server_frame,
            placeholder_text="Port"
        )
        self.port_entry.insert(0, "5555")
        self.port_entry.pack(side="left", expand=True, padx=5)
        
        # Username
        self.username_entry = ctk.CTkEntry(
            self.login_frame,
            placeholder_text="Username",
            width=300
        )
        self.username_entry.pack(pady=10)
        
        # Connect button
        self.connect_btn = ctk.CTkButton(
            self.login_frame,
            text="Connect",
            command=self.connect_to_server
        )
        self.connect_btn.pack(pady=10)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            self.login_frame,
            text="",
            text_color="red"
        )
        self.status_label.pack(pady=10)

    def create_chat_frame(self):
        self.chat_frame = ctk.CTkFrame(self.window)
        
        # Chat area
        self.chat_text = ctk.CTkTextbox(
            self.chat_frame,
            wrap="word",
            font=("Arial", 12)
        )
        self.chat_text.pack(expand=True, fill="both", padx=10, pady=(10, 5))
        self.chat_text.configure(state="disabled")
        
        # Animation label
        self.animation_label = ctk.CTkLabel(
            self.chat_frame,
            text="",
            font=("Arial", 10),
            text_color="#888888"
        )
        self.animation_label.pack(pady=(0, 5))
        
        # Message entry area
        message_frame = ctk.CTkFrame(self.chat_frame)
        message_frame.pack(fill="x", padx=10, pady=(5, 10))
        
        self.message_entry = ctk.CTkEntry(
            message_frame,
            placeholder_text="Type your message...",
        )
        self.message_entry.pack(side="left", expand=True, fill="x", padx=(0, 5))
        
        # Add Show Encryption Window button
        self.show_encryption_btn = ctk.CTkButton(
            message_frame,
            text="🔒",
            width=40,
            command=self.toggle_encryption_window
        )
        self.show_encryption_btn.pack(side="right", padx=(0, 5))
        
        send_btn = ctk.CTkButton(
            message_frame,
            text="Send",
            width=100,
            command=self.send_message
        )
        send_btn.pack(side="right")
        
        # Bind Enter key to send message
        self.message_entry.bind("<Return>", lambda e: self.send_message())

    def toggle_encryption_window(self):
        if not self.encryption_window or not self.encryption_window.winfo_exists():
            self.encryption_window = EncryptedMessageDialog(self.window)
        else:
            self.encryption_window.destroy()
            self.encryption_window = None

    def update_chat(self, message, message_type="message"):
        self.chat_text.configure(state="normal")
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if message_type == "system":
            self.chat_text.insert("end", f"[{timestamp}] {message}\n", "system")
            self.chat_text.tag_config("system", foreground="#888888")
        else:
            self.chat_text.insert("end", f"[{timestamp}] {message}\n")
        
        self.chat_text.configure(state="disabled")
        self.chat_text.see("end")

    def connect_to_server(self):
        if self.is_connected:
            return
        
        host = self.host_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            self.status_label.configure(text="Invalid port number")
            return
        
        username = self.username_entry.get()
        if not username:
            self.status_label.configure(text="Please enter a username")
            return
        
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect((host, port))
            
            # Send username
            username_bytes = username.encode('utf-8')
            username_length = len(username_bytes).to_bytes(4, 'big')
            self.client.send(username_length)
            self.client.send(username_bytes)
            
            # Receive encryption key from server
            self.key = self.client.recv(16)
            self.aes = AES(self.key)
            
            # Start receiving messages
            self.is_connected = True
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Switch to chat frame
            self.login_frame.pack_forget()
            self.chat_frame.pack(expand=True, fill="both", padx=20, pady=20)
            
            # Update chat with welcome message
            self.update_chat(f"Connected to server as {username}", "system")
            
        except Exception as e:
            self.status_label.configure(text=f"Connection failed: {str(e)}")

    def receive_messages(self):
        while self.is_connected:
            try:
                # Receive message length
                msg_length = int.from_bytes(self.client.recv(4), 'big')
                if msg_length == 0:
                    break

                # Receive encrypted message
                encrypted_message = self.client.recv(msg_length)
                if not encrypted_message:
                    break

                # Decrypt message
                iv = encrypted_message[:16]  # First 16 bytes are IV
                ciphertext = encrypted_message[16:]  # Rest is ciphertext
                decrypted_message = self.aes.decrypt_ctr(ciphertext, iv)
                self.update_chat(decrypted_message.decode('utf-8'))

            except Exception as e:
                print(f"Error receiving message: {e}")
                break
        
        self.is_connected = False
        self.window.after(0, self.handle_disconnect)

    def handle_disconnect(self):
        self.chat_frame.pack_forget()
        self.login_frame.pack(expand=True, fill="both", padx=20, pady=20)
        self.status_label.configure(text="Disconnected from server")
        self.connect_btn.configure(state="normal")
        if self.client:
            self.client.close()

    def send_message(self):
        if not self.is_connected:
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        try:
            # Generate new IV for each message
            iv = os.urandom(16)
            encrypted_message = self.aes.encrypt_ctr(message.encode(), iv)
            
            # Update encryption window if it exists
            if self.encryption_window and self.encryption_window.winfo_exists():
                self.encryption_window.update_content(message, encrypted_message)
            
            # Start the encryption animation
            self.start_encryption_animation(message, encrypted_message)
            
            # Send message length first (including IV)
            full_message = iv + encrypted_message
            message_length = len(full_message).to_bytes(4, 'big')
            self.client.send(message_length)
            self.client.send(full_message)
            
            # Clear message entry
            self.message_entry.delete(0, "end")
            
        except Exception as e:
            self.update_chat(f"Error sending message: {str(e)}", "system")
            self.is_connected = False
            self.handle_disconnect()

    def start_encryption_animation(self, original_message, encrypted_message):
        if self.animation_thread and self.animation_thread.is_alive():
            self.animation_thread.join()
        
        self.animation_thread = threading.Thread(
            target=self._run_encryption_animation,
            args=(original_message, encrypted_message)
        )
        self.animation_thread.start()

    def _run_encryption_animation(self, original_message, encrypted_message):
        steps = 10
        for i in range(steps + 1):
            encrypted_portion = encrypted_message[:int(len(encrypted_message) * i / steps)]
            displayed_text = original_message[:len(original_message) - len(encrypted_portion)] + encrypted_portion.hex()[:len(encrypted_portion)]
            self.window.after(0, self.animation_label.configure, {"text": f"Encrypting: {displayed_text}"})
            time.sleep(0.1)
        
        time.sleep(0.5)  # Keep the final encrypted message visible for a moment
        self.window.after(0, self.animation_label.configure, {"text": ""})

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = ChatGUI()
    app.run()