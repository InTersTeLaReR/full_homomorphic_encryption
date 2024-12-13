import streamlit as st
from phe import paillier
import time
import matplotlib.pyplot as plt
import numpy as np

# Initialize session state variables
if "public_key" not in st.session_state:
    public_key, private_key = paillier.generate_paillier_keypair()
    st.session_state.public_key = public_key
    st.session_state.private_key = private_key

if "encrypted_transactions" not in st.session_state:
    st.session_state.encrypted_transactions = {}

if "transaction_history" not in st.session_state:
    st.session_state.transaction_history = []

if "wallet" not in st.session_state:
    st.session_state.wallet = []  # Store deposits as a list of dictionaries

if "last_passkey_change_time" not in st.session_state:
    st.session_state.last_passkey_change_time = time.time()

# Encryption and decryption functions
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

# Navigation and Wallet Management
st.title("PrivShare – Highlighting privacy-focused")
st.write("Welcome to the platform where you can securely submit and manage your financial data.")

if "nav_section" not in st.session_state:
    st.session_state.nav_section = "Home"

def navigate_to(section):
    st.session_state.nav_section = section

st.sidebar.header("Navigation")
nav_buttons = {
    "Home": "Home",
    "FAQ's": "FAQ's",
    "Support": "Support",
    "Bank & Mandates": "Bank & Mandates",
    "Settings": "Settings",
    "Graph Chart": "Graph Chart",
    "Wallet": "Wallet",  # Wallet added
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

                st.session_state.wallet.append({
                    "amount": float(transaction_amount),
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
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

elif nav_section == "Wallet":
    st.header("Wallet")
    st.write("Here you can view your total deposits and transaction history.")

    total_deposit = sum([entry['amount'] for entry in st.session_state.wallet])
    st.subheader(f"Total Deposited Amount: ₹ {total_deposit:.2f}")

    if st.session_state.wallet:
        st.write("### Deposit History")
        for idx, entry in enumerate(st.session_state.wallet, 1):
            st.write(f"{idx}. Amount: ₹{entry['amount']}, Date: {entry['timestamp']}")
    else:
        st.write("No deposits made yet.")

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

elif nav_section == "Bank & Mandates":
    st.header("Bank & Mandates")
    st.write("This section provides access to bank mandates and transactions related to financial institutions.")

elif nav_section == "Settings":
    st.header("Settings")
    st.write("Here, you can manage your account settings.")

elif nav_section == "Graph Chart":
    st.header("Transaction Chart")
    st.write("Here is a graphical representation of transaction amounts over time.")

    transaction_amounts = [float(transaction['transaction_amount']) for transaction in st.session_state.transaction_history]
    transaction_times = [time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) for _ in st.session_state.transaction_history]

    if transaction_amounts:
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

# Add a section to display encrypted transactions in the sidebar at the bottom
st.sidebar.write("### Encrypted Transactions")
if st.session_state.encrypted_transactions:
    for user_id, encrypted_data in st.session_state.encrypted_transactions.items():
        st.sidebar.write(f"User ID: {user_id}, Encrypted Amount: {encrypted_data.ciphertext()}")
else:
    st.sidebar.write("No encrypted transactions yet.")

# Add a small text bar at the bottom of the page
st.markdown("<div style='position: fixed; bottom: 0; width: 100%; text-align: center; background-color: #f0f0f0; padding: 5px;'>Encrypted Homomorphic Message: Securely Encrypted for Privacy</div>", unsafe_allow_html=True)
