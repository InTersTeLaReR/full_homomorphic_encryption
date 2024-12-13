import streamlit as st
from phe import paillier
import time

# Paillier Key Generation
if "public_key" not in st.session_state:
    public_key, private_key = paillier.generate_paillier_keypair()
    st.session_state.public_key = public_key
    st.session_state.private_key = private_key

# Initialize encrypted transactions and history
if "encrypted_transactions" not in st.session_state:
    st.session_state.encrypted_transactions = {}

if "transaction_history" not in st.session_state:
    st.session_state.transaction_history = []

# Store the time when the passkey was last changed
if "last_passkey_change_time" not in st.session_state:
    st.session_state.last_passkey_change_time = time.time()

# Encryption and Decryption Functions
def encrypt_data(data):
    encrypted_data = st.session_state.public_key.encrypt(float(data))
    return encrypted_data

def decrypt_data(encrypted_data):
    return st.session_state.private_key.decrypt(encrypted_data)

# Function to get the current passkey
def get_current_passkey():
    elapsed_time = time.time() - st.session_state.last_passkey_change_time
    if elapsed_time > 300:  
        st.session_state.last_passkey_change_time = time.time()  
        return "sit4321" if (int(elapsed_time / 300) % 2 == 1) else "sit1234"
    else:
        return "sit1234" if (int(elapsed_time / 300) % 2 == 0) else "sit4321"

# Function to display countdown for passkey change
def display_countdown():
    elapsed_time = time.time() - st.session_state.last_passkey_change_time
    remaining_time = 300 - elapsed_time  
    if remaining_time > 0:
        st.write(f"Time until next passkey change: {int(remaining_time)} seconds")
    else:
        st.write("Passkey has been updated!")

# Streamlit UI
st.title("Secure Financial Data Platform")
st.write("Welcome to the platform where you can securely submit and manage your financial data.")

# Navigation Section
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

        # User input fields
        user_id = st.text_input("Enter User ID:")
        transaction_amount = st.text_input("Enter Transaction Amount (numeric):")

        # Display passkey and countdown
        current_passkey = get_current_passkey()
        display_countdown()
        passkey = st.text_input("Enter Passkey:", type="password")

        # Handle data submission
        if st.button("Encrypt and Submit"):
            if user_id and transaction_amount.replace('.', '', 1).isdigit() and passkey == current_passkey:
                encrypted_data = encrypt_data(transaction_amount)
                # Store encrypted transaction
                st.session_state.encrypted_transactions[user_id] = encrypted_data
                # Save transaction history
                st.session_state.transaction_history.append({
                    "user_id": user_id,
                    "transaction_amount": transaction_amount,
                    "status": "Encrypted and stored securely"
                })
                st.success("Transaction encrypted and stored securely!")
            elif passkey != current_passkey:
                st.error("Invalid passkey! Please try again.")
            else:
                st.error("Please enter valid transaction data.")

        # Display Transaction History
        st.subheader("Transaction History")
        if st.session_state.transaction_history:
            for idx, transaction in enumerate(st.session_state.transaction_history, 1):
                st.write(f"{idx}. User ID: {transaction['user_id']}, Amount: {transaction['transaction_amount']}, Status: {transaction['status']}")
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

elif nav_section == "Bank & Mandates":
    st.header("Bank & Mandates")
    st.write("This section provides access to bank mandates and transactions related to financial institutions.")
    st.write("Here, you can link your bank account, manage mandates, and view related activities.")

elif nav_section == "Settings":
    st.header("Settings")
    st.write("Here, you can manage your account settings.")
    st.write("Options include changing your password, updating your profile, and configuring notification preferences.")

elif nav_section == "Logout":
    st.header("Logout")
    st.write("You have successfully logged out. To log in again, return to the Home section.")

st.sidebar.header("Encrypted Data Overview")
st.sidebar.json({user: {"ciphertext": str(data.ciphertext()), "exponent": data.exponent} for user, data in st.session_state.encrypted_transactions.items()})
