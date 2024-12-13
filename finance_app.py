import streamlit as st
from phe import paillier
import time
import matplotlib.pyplot as plt
import numpy as np
import psutil  # Import psutil for real-time network traffic monitoring

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

if "encryption_method" not in st.session_state:
    st.session_state.encryption_method = "HE"  # Default to Homomorphic Encryption (HE)

if "user_authenticated" not in st.session_state:
    st.session_state.user_authenticated = False

# Encryption and decryption functions for HE (Paillier)
def encrypt_data(data):
    if st.session_state.encryption_method == "HE":
        encrypted_data = st.session_state.public_key.encrypt(float(data))
    elif st.session_state.encryption_method == "FFHE":
        # Use FHE encryption function (this is a placeholder)
        encrypted_data = encrypt_data_fhe(data)  # Replace with actual FHE encryption function
    return encrypted_data

def decrypt_data(encrypted_data):
    if st.session_state.encryption_method == "HE":
        return st.session_state.private_key.decrypt(encrypted_data)
    elif st.session_state.encryption_method == "FFHE":
        # Use FHE decryption function (this is a placeholder)
        return decrypt_data_fhe(encrypted_data)  # Replace with actual FHE decryption function

# Placeholder FHE encryption and decryption (replace with actual FHE library functions)
def encrypt_data_fhe(data):
    # FHE encryption logic should go here
    return data  # Placeholder, replace with actual FHE encryption

def decrypt_data_fhe(encrypted_data):
    # FHE decryption logic should go here
    return encrypted_data  # Placeholder, replace with actual FHE decryption

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

# Function to simulate network traffic monitoring for suspicious activity
def check_network_traffic():
    # Get network statistics using psutil
    network_stats = psutil.net_io_counters()
    bytes_sent = network_stats.bytes_sent / (1024 * 1024)  # Convert bytes to MB
    bytes_recv = network_stats.bytes_recv / (1024 * 1024)  # Convert bytes to MB

    total_network_traffic = bytes_sent + bytes_recv  # Total network traffic in MB
    return total_network_traffic

# Display network traffic status
network_traffic = check_network_traffic()
suspicious_activity = False  # Placeholder logic for suspicious activity
if suspicious_activity:
    st.markdown(
        '<p style="color:red; text-align:center; font-size:20px; font-weight:bold;">⚠️ Suspicious network activity detected! ⚠️</p>',
        unsafe_allow_html=True
    )
else:
    st.markdown(
        '<p style="color:green; text-align:center; font-size:20px; font-weight:bold;">✔️ No suspicious activity detected.</p>',
        unsafe_allow_html=True
    )

st.write(f"Total Network Traffic: {network_traffic:.2f} MB")

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
    "Settings": "Settings",
    "Graph Chart": "Graph Chart",
    "Spending Analysis": "Spending Analysis",  # Added Spending Analysis
    "Encrypted Data": "Encrypted Data",  # Added Encrypted Data
    "Wallet": "Wallet",  # Wallet added
    "Logout": "Logout",
}

for label, section in nav_buttons.items():
    if st.sidebar.button(label):
        navigate_to(section)

nav_section = st.session_state.nav_section

if nav_section == "Home":
    st.header("Home")

    if not st.session_state.user_authenticated:
        st.subheader("User Authentication")
        user_password = st.text_input("Enter User Passkey:", type="password")

        if st.button("Authenticate User"):
            if user_password == "user123":
                st.session_state.user_authenticated = True
                st.success("User authenticated successfully!")
            else:
                st.error("Invalid passkey! Please try again.")

    if st.session_state.user_authenticated:
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

elif nav_section == "Settings":
    st.header("Settings")
    st.write("Here, you can manage your account settings.")

    # Toggle to switch between encryption methods
    encryption_method = st.radio(
        "Select Encryption Method",
        options=["HE", "FFHE"],
        index=0 if st.session_state.encryption_method == "HE" else 1
    )
    if encryption_method != st.session_state.encryption_method:
        st.session_state.encryption_method = encryption_method
        st.success(f"Switched to {encryption_method} encryption method.")

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

elif nav_section == "Spending Analysis":
    st.header("Spending Analysis")
    st.write("Here, you can analyze your spending patterns.")

    if st.session_state.wallet:
        total_spent = sum([entry['amount'] for entry in st.session_state.wallet])
        st.subheader(f"Total Spent: ₹ {total_spent:.2f}")

        # Create a line graph for spending distribution
        spending_distribution = [entry['amount'] for entry in st.session_state.wallet]
        spending_labels = [f"Transaction {i+1}" for i in range(len(spending_distribution))]

        # Line graph representation
        fig, ax = plt.subplots()
        ax.plot(spending_labels, spending_distribution, marker='o', color='orange', linestyle='-', linewidth=2)
        ax.set_xlabel('Transaction')
        ax.set_ylabel('Amount (₹)')
        ax.set_title('Spending Distribution Over Time')
        st.pyplot(fig)

        # Display detailed transaction data in a table
        st.write("### Detailed Spending Table")
        st.table(st.session_state.wallet)

    else:
        st.write("No spending data available.")

elif nav_section == "Encrypted Data":
    st.header("Encrypted Transaction Data")
    st.write("Here is the encrypted data for each transaction.")

    if st.session_state.encrypted_transactions:
        for user_id, encrypted_data in st.session_state.encrypted_transactions.items():
            st.write(f"**User ID:** {user_id}, Encrypted Amount: {encrypted_data.ciphertext()}")
    else:
        st.write("No encrypted transactions yet.")

elif nav_section == "Logout":
    st.header("Logout")
    st.write("You have successfully logged out.")

# Timer Logic
if "logout_time" not in st.session_state:
    st.session_state.logout_time = time.time() + 300  # Set 5 minutes timer (300 seconds)

# Calculate remaining time
elapsed_time = time.time() - st.session_state.logout_time + 300
