import streamlit as st
from phe import paillier
import time
import matplotlib.pyplot as plt
import numpy as np

if "public_key" not in st.session_state:
    public_key, private_key = paillier.generate_paillier_keypair()
    st.session_state.public_key = public_key
    st.session_state.private_key = private_key

if "encrypted_transactions" not in st.session_state:
    st.session_state.encrypted_transactions = {}

if "transaction_history" not in st.session_state:
    st.session_state.transaction_history = []

if "last_passkey_change_time" not in st.session_state:
    st.session_state.last_passkey_change_time = time.time()

def encrypt_data(data):
    encrypted_data = st.session_state.public_key.encrypt(float(data))
    return encrypted_data

def decrypt_data(encrypted_data):
    return st.session_state.private_key.decrypt(encrypted_data)

def get_current_passkey():
    elapsed_time = time.time() - st.session_state.last_passkey_change_time
    if elapsed_time > 300:  
        st.session_state.last_passkey_change_time = time.time()  
        return "sit4321" if (int(elapsed_time / 300) % 2 == 1) else "sit1234"
    else:
        return "sit1234" if (int(elapsed_time / 300) % 2 == 0) else "sit4321"

def display_countdown():
    elapsed_time = time.time() - st.session_state.last_passkey_change_time
    remaining_time = 300 - elapsed_time  
    if remaining_time > 0:
        st.write(f"Time until next passkey change: {int(remaining_time)} seconds")
    else:
        st.write("Passkey has been updated!")

st.title("PrivShare – Highlighting privacy-focused")
st.write("Welcome to the platform where you can securely submit and manage your financial data.")

if "nav_section" not in st.session_state:
    st.session_state.nav_section = "Home"

st.sidebar.header("Navigation")
def navigate_to(section):
    st.session_state.nav_section = section

nav_buttons = {
    "Home": "Home",
    "FAQ's": "FAQ's",
    "Support": "Support",
    "Bank & Mandates": "Bank & Mandates",
    "Settings": "Settings",
    "Graph Chart": "Graph Chart",
    "Logout": "Logout",
}

for label, section in nav_buttons.items():
    if st.sidebar.button(label):
        navigate_to(section)

nav_section = st.session_state.nav_section

if nav_section == "Home":
    st.header("Home")
    section = st.selectbox("Select Section", ["User Section", "Admin Section"])

    if section == "User Section":
        st.subheader("Submit Financial Data")

        user_id = st.text_input("Enter User ID:")
        pan_no = st.text_input("Enter PAN Number:")
        transaction_amount = st.text_input("Enter Transaction Amount (numeric):")

        current_passkey = get_current_passkey()
        display_countdown()
        passkey = st.text_input("Enter Passkey:", type="password")


        if st.button("Encrypt and Submit"):
            if user_id and pan_no and transaction_amount.replace('.', '', 1).isdigit() and passkey == current_passkey:
                encrypted_data = encrypt_data(transaction_amount)

                st.session_state.encrypted_transactions[user_id] = encrypted_data

                st.session_state.transaction_history.append({
                    "user_id": user_id,
                    "pan_no": pan_no,  
                    "transaction_amount": transaction_amount,
                    "status": "Encrypted and stored securely"
                })
                st.success("Transaction encrypted and stored securely!")
            elif passkey != current_passkey:
                st.error("Invalid passkey! Please try again.")
            else:
                st.error("Please enter valid transaction data.")

        st.subheader("Transaction History")
        if st.session_state.transaction_history:
            for idx, transaction in enumerate(st.session_state.transaction_history, 1):
                st.write(f"{idx}. User ID: {transaction['user_id']}, PAN No: {transaction['pan_no']}, Amount: {transaction['transaction_amount']}, Status: {transaction['status']}")
        else:
            st.write("No transactions submitted yet.")

    elif section == "Admin Section":
        st.subheader("Admin Panel")
        admin_password = st.text_input("Enter Admin Access Code:", type="password")
        if st.button("Access Admin Panel"):
            if admin_password == "admin123": 
                st.success("Access granted!")
                if st.session_state.encrypted_transactions:
                    st.write("### Decrypted Financial Transactions")
                    for user, encrypted_data in st.session_state.encrypted_transactions.items():
                        try:
                            decrypted_amount = decrypt_data(encrypted_data)
                            st.write(f"**User ID:** {user}, **Transaction Amount:** {decrypted_amount}")
                        except ValueError as e:
                            st.error(f"Error decrypting data for User ID {user}: {e}")
                else:
                    st.info("No transactions to display.")
            else:
                st.error("Incorrect access code! Access denied.")

elif nav_section == "FAQ's":
    st.header("Frequently Asked Questions")
    st.write(""" 
    1. **How do I submit my financial data?**
       - You can securely submit your financial data through the "User Section" of the platform.
    2. **What is encryption?**
       - Encryption is a process that converts data into a secure format to prevent unauthorized access.
    3. **How do I access the Admin Panel?**
       - Only authorized users with an admin access code can access the Admin Panel.
    4. **How is my data protected?**
       - Your data is encrypted using Paillier homomorphic encryption, ensuring its confidentiality and security.
    """)

elif nav_section == "Support":
    st.header("Support")
    st.write("For assistance with the platform, please contact us at the following:")
    st.write("Email: support@secureplatform.com")
    st.write("Phone: +1-234-567-890")
    st.write("Our team is available 24/7 to assist you.")

    st.subheader("Chat with Us")
    
    if "messages" not in st.session_state:
        st.session_state.messages = []

    def get_bot_reply(user_input):
        
        replies = {
            "hi": "Hello! How can I assist you today?",
            "help": "Please describe the issue you're facing, and I'll do my best to help.",
            "investment": "Here is some information about investments: You can diversify your portfolio through stocks, bonds, and mutual funds.",
            "holdings": "Your holdings refer to the assets you own, such as stocks, bonds, or real estate investments.",
            "sport": "Sports news includes the latest updates on football, basketball, and other events happening globally.",
            "news": "Stay updated with the latest world news covering politics, business, and more.",
            "crypto": "Cryptocurrency involves digital currencies such as Bitcoin, Ethereum, and others that use blockchain technology."
        }
        return replies.get(user_input.lower(), "Sorry, I didn't understand that. Please try again.")

    
    if "step" not in st.session_state:
        st.session_state.step = 0  
    
    user_input = st.text_input("Your Message:", "")

    if user_input:
        st.session_state.messages.append(f"You: {user_input}")
        if st.session_state.step == 0:
            if user_input.lower() == "hi":
                bot_reply = get_bot_reply("hi")
                st.session_state.step = 1  
                st.session_state.messages.append(f"Bot: {bot_reply}")
            else:
                bot_reply = "Please say 'hi' to start the conversation."
                st.session_state.messages.append(f"Bot: {bot_reply}")
        elif st.session_state.step == 1:
            if user_input.lower() == "investment":
                bot_reply = get_bot_reply("investment")
                st.session_state.step = 2
            elif user_input.lower() == "holdings":
                bot_reply = get_bot_reply("holdings")
                st.session_state.step = 2
            else:
                bot_reply = "Please choose between 'Investment' or 'Holdings'."
            st.session_state.messages.append(f"Bot: {bot_reply}")
        elif st.session_state.step == 2:
            if user_input.lower() == "sport":
                bot_reply = get_bot_reply("sport")
            elif user_input.lower() == "news":
                bot_reply = get_bot_reply("news")
            elif user_input.lower() == "crypto":
                bot_reply = get_bot_reply("crypto")
            else:
                bot_reply = "Please select between 'Sport', 'News', or 'Crypto'."
            st.session_state.messages.append(f"Bot: {bot_reply}")
            st.session_state.step = 0  

    
    for message in st.session_state.messages:
        st.write(message)

elif nav_section == "Bank & Mandates":
    st.header("Bank & Mandates")
    st.write("This section provides access to bank mandates and transactions related to financial institutions.")
    st.write("Here, you can link your bank account, manage mandates, and view related activities.")

elif nav_section == "Settings":
    st.header("Settings")
    st.write("Here, you can manage your account settings.")
    st.write("Options include changing your password, updating your profile, and configuring notification preferences.")

elif nav_section == "Graph Chart":
    st.header("Transaction Chart")
    st.write("Here is a graphical representation of transaction amounts over time.")

    user_ids = [transaction['user_id'] for transaction in st.session_state.transaction_history]
    transaction_amounts = [float(transaction['transaction_amount']) for transaction in st.session_state.transaction_history]
    transaction_times = [time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) for _ in st.session_state.transaction_history]

    if user_ids:
        fig, ax = plt.subplots()
        ax.bar(transaction_times, transaction_amounts, color='skyblue')
        ax.set_xlabel('Date and Time')
        ax.set_ylabel('Transaction Amount')
        ax.set_title('Transaction Amounts Over Time')
        st.pyplot(fig)
    else:
        st.write("No transactions to display in the graph.")

elif nav_section == "Logout":
    st.header("Logout")
    st.write("You have successfully logged out. To log in again, return to the Home section.")

st.sidebar.header("Encrypted Data Overview")
st.sidebar.json({user: {"ciphertext": str(data.ciphertext()), "exponent": data.exponent} for user, data in st.session_state.encrypted_transactions.items()})
