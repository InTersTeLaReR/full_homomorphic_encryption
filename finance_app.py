#for sit hackathon by team codesmith...Had a wonderfull experience
import streamlit as st
from phe import paillier
import time
import matplotlib.pyplot as plt
import numpy as np
import psutil
from cryptography.fernet import Fernet  # For file-based encryption

if "public_key" not in st.session_state:
    public_key, private_key = paillier.generate_paillier_keypair()
    st.session_state.public_key = public_key
    st.session_state.private_key = private_key

if "encrypted_transactions" not in st.session_state:
    st.session_state.encrypted_transactions = {}

if "transaction_history" not in st.session_state:
    st.session_state.transaction_history = []

if "wallet" not in st.session_state:
    st.session_state.wallet = []

if "last_passkey_change_time" not in st.session_state:
    st.session_state.last_passkey_change_time = time.time()

if "encryption_method" not in st.session_state:
    st.session_state.encryption_method = "HE"

if "user_authenticated" not in st.session_state:
    st.session_state.user_authenticated = False

if "user_id" not in st.session_state:
    st.session_state.user_id = ""

if "pan_no" not in st.session_state:
    st.session_state.pan_no = ""


def encrypt_data(data):
    if st.session_state.encryption_method == "HE":
        encrypted_data = st.session_state.public_key.encrypt(float(data))
    elif st.session_state.encryption_method == "FFHE":
        encrypted_data = encrypt_data_fhe(data)
    return encrypted_data


def decrypt_data(encrypted_data):
    if st.session_state.encryption_method == "HE":
        return st.session_state.private_key.decrypt(encrypted_data)
    elif st.session_state.encryption_method == "FFHE":
        return decrypt_data_fhe(encrypted_data)


def encrypt_data_fhe(data):
    return data


def decrypt_data_fhe(encrypted_data):
    return encrypted_data


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


def check_network_traffic():
    network_stats = psutil.net_io_counters()
    bytes_sent = network_stats.bytes_sent / (1024 * 1024)
    bytes_recv = network_stats.bytes_recv / (1024 * 1024)
    total_network_traffic = bytes_sent + bytes_recv
    return total_network_traffic


network_traffic = check_network_traffic()
suspicious_activity = False
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
    "Spending Analysis": "Spending Analysis",
    "Encrypted Data": "Encrypted Data",
    "Wallet": "Wallet",
    "Credential Encryption": "Credential Encryption", 
     "Withdraw": "Withdraw", 
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

            st.session_state.user_id = st.text_input("Enter User ID:", value=st.session_state.user_id)
            st.session_state.pan_no = st.text_input("Enter PAN Number:", value=st.session_state.pan_no)
            transaction_amount = st.text_input("Enter Transaction Amount (numeric):")

            if not transaction_amount:
                transaction_amount = '0000'

            current_passkey = get_current_passkey()
            display_countdown()
            passkey = st.text_input("Enter Passkey:", type="password")

            if st.button("Encrypt and Submit"):
                if st.session_state.user_id and st.session_state.pan_no and transaction_amount.replace('.', '', 1).isdigit() and passkey == current_passkey:
                    encrypted_data = encrypt_data(transaction_amount)
                    st.session_state.encrypted_transactions[st.session_state.user_id] = encrypted_data

                    st.session_state.transaction_history.append({
                        "user_id": st.session_state.user_id,
                        "pan_no": st.session_state.pan_no,
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
#HE updated
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

    user_input = st.radio("Choose a topic:", ("Investment", "Deposition"))

    if user_input == "Investment":
        st.write("""
        **Investment** involves allocating money into financial instruments with the expectation of generating returns over time. Common investment options include stocks, bonds, real estate, and mutual funds. By investing, individuals aim to grow their wealth, achieve financial goals, and beat inflation. It's important to diversify investments and understand the associated risks. A well-planned investment strategy can help achieve long-term financial stability.
        """)

    elif user_input == "Deposition":
        st.write("""
        **Deposition** refers to the act of placing or depositing money into a secure account, such as a bank account or savings account. It allows individuals to safeguard their funds and earn interest over time. Depositing money is a safe way to preserve capital while earning a small return through interest. Deposits are generally low-risk investments, offering liquidity and security for the depositor's funds.
        """)

elif nav_section == "Withdraw":
    st.header("Withdraw Funds")
    st.write("Here, you can withdraw funds from your wallet.")

    if st.session_state.wallet:
        total_balance = sum([entry['amount'] for entry in st.session_state.wallet])
        st.subheader(f"Available Balance: ₹ {total_balance:.2f}")

        withdraw_amount = st.number_input("Enter Amount to Withdraw:", min_value=0.0, max_value=total_balance, step=0.01)

        if st.button("Confirm Withdrawal"):
            if withdraw_amount <= total_balance:
                st.session_state.wallet.append({
                    "amount": -withdraw_amount,
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                })
                st.success(f"The amount will be delivered within 24 hours, Withdraw request added ₹ {withdraw_amount:.2f}. Remaining Balance: ₹ {total_balance - withdraw_amount:.2f}")
            else:
                st.error("Insufficient balance!")
    else:
        st.write("No funds available in your wallet.")


elif nav_section == "Settings":
    st.header("Settings")
    st.write("Here, you can manage your account settings.")

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

        spending_distribution = [entry['amount'] for entry in st.session_state.wallet]
        spending_labels = [f"Transaction {i+1}" for i in range(len(spending_distribution))]

        fig, ax = plt.subplots()
        ax.plot(spending_labels, spending_distribution, marker='o', color='orange', linestyle='-', linewidth=2)
        ax.set_xlabel('Transaction')
        ax.set_ylabel('Amount (₹)')
        ax.set_title('Spending Distribution Over Time')
        ax.grid(True)
        st.pyplot(fig)

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

elif nav_section == "Credential Encryption":
    st.header("Credential Encryption")
    st.write("Upload a text file containing user credentials to encrypt them.")

    uploaded_file = st.file_uploader("Upload Credential File", type=["txt"])

    if uploaded_file:
        content = uploaded_file.read().decode("utf-8")
        key = Fernet.generate_key()  # Generate a key for file encryption
        cipher_suite = Fernet(key)
        encrypted_credentials = cipher_suite.encrypt(content.encode())

        st.write("Encrypted Credentials:")
        st.text(encrypted_credentials.decode())

elif nav_section == "Logout":
    st.header("Logout")
    st.write("You have successfully logged out.")

    st.session_state.user_authenticated = False
    st.session_state.user_id = ""
    st.session_state.pan_no = ""
    st.session_state.encrypted_transactions = {}
    st.session_state.transaction_history = []
    st.session_state.wallet = []

