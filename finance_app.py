import streamlit as st
from phe import paillier
import time

# Generate keys and initialize session state variables
if "public_key" not in st.session_state:
    public_key, private_key = paillier.generate_paillier_keypair()
    st.session_state.public_key = public_key
    st.session_state.private_key = private_key

if "encrypted_transactions" not in st.session_state:
    st.session_state.encrypted_transactions = {}

if "last_passkey_change_time" not in st.session_state:
    st.session_state.last_passkey_change_time = time.time()

# Encryption and Decryption functions
def encrypt_data(data):
    encrypted_data = st.session_state.public_key.encrypt(float(data))
    return encrypted_data

def decrypt_data(encrypted_data):
    return st.session_state.private_key.decrypt(encrypted_data)

# Function to determine the current passkey and display countdown
def get_current_passkey():
    elapsed_time = time.time() - st.session_state.last_passkey_change_time
    if elapsed_time > 300:  # If 5 minutes have passed
        st.session_state.last_passkey_change_time = time.time()  # Reset the change time
        return "sit4321" if (int(elapsed_time / 300) % 2 == 1) else "sit1234"
    else:
        return "sit1234" if (int(elapsed_time / 300) % 2 == 0) else "sit4321"

# Function to display the countdown for passkey change
def display_countdown():
    elapsed_time = time.time() - st.session_state.last_passkey_change_time
    remaining_time = 300 - elapsed_time  # 300 seconds (5 minutes)
    if remaining_time > 0:
        st.write(f"Time until next passkey change: {int(remaining_time)} seconds")
    else:
        st.write("Passkey has been updated!")

# Sidebar Navigation with Cards
st.sidebar.title("Navigation")

# Create columns for the cards
card_columns = st.sidebar.columns(2)

# Define the sections as cards
card_section = None
with card_columns[0]:
    if st.button("Home", use_container_width=True):
        card_section = "Home"
with card_columns[1]:
    if st.button("FAQ's", use_container_width=True):
        card_section = "FAQ's"
with card_columns[0]:
    if st.button("Support", use_container_width=True):
        card_section = "Support"
with card_columns[1]:
    if st.button("Bank & Mandates", use_container_width=True):
        card_section = "Bank & Mandates"
with card_columns[0]:
    if st.button("Settings", use_container_width=True):
        card_section = "Settings"
with card_columns[1]:
    if st.button("Logout", use_container_width=True):
        card_section = "Logout"

# Home Section
if card_section == "Home":
    st.title("PrivShare – आपके डेटा की सुरक्षा, आपकी पहचान की रक्षा")
    st.write("Welcome to the platform where you can securely submit and manage your financial data.")

    # Dropdown for user/admin sections
    section = st.selectbox("Select Section", ["User Section", "Admin Section"])

    # User Section
    if section == "User Section":
        st.header("Submit Financial Data")

        # User inputs financial data
        user_id = st.text_input("Enter User ID:")
        transaction_amount = st.text_input("Enter Transaction Amount (numeric):")

        # Get current passkey
        current_passkey = get_current_passkey()

        # Display countdown
        display_countdown()

        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt and Submit"):
            if user_id and transaction_amount.replace('.', '', 1).isdigit() and passkey == current_passkey:
                encrypted_data = encrypt_data(transaction_amount)
                st.session_state.encrypted_transactions[user_id] = encrypted_data
                st.success("Transaction encrypted and stored securely!")
            elif passkey != current_passkey:
                st.error("Invalid passkey! Please try again.")
            else:
                st.error("Please enter valid transaction data.")

    # Admin Section
    elif section == "Admin Section":
        st.header("Admin Panel")

        # Admin authentication
        admin_password = st.text_input("Enter Admin Access Code:", type="password")
        if st.button("Access Admin Panel"):
            if admin_password == "admin123":  # Replace with a secure authentication method
                st.success("Access granted!")
                if st.session_state.encrypted_transactions:
                    st.write("### Decrypted Financial Transactions")
                    # Display decrypted data
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

# FAQ Section
elif card_section == "FAQ's":
    st.title("Frequently Asked Questions")
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

# Support Section
elif card_section == "Support":
    st.title("Support")
    st.write("For assistance with the platform, please contact us at the following:")
    st.write("Email: support@secureplatform.com")
    st.write("Phone: +1-234-567-890")
    st.write("Our team is available 24/7 to assist you.")

# Bank & Mandates Section
elif card_section == "Bank & Mandates":
    st.title("Bank & Mandates")
    st.write("This section provides access to bank mandates and transactions related to financial institutions.")
    st.write("Here, you can link your bank account, manage mandates, and view related activities.")

# Settings Section
elif card_section == "Settings":
    st.title("Settings")
    st.write("Here, you can manage your account settings.")
    st.write("Options include changing your password, updating your profile, and configuring notification preferences.")

# Logout Section
elif card_section == "Logout":
    st.title("Logout")
    st.write("You have successfully logged out. To log in again, return to the Home section.")

# Optional: Display encrypted data storage for demonstration
st.sidebar.header("Encrypted Data Overview")
# Convert encrypted data to a string for JSON display
st.sidebar.json({user: {"ciphertext": str(data.ciphertext()), "exponent": data.exponent} for user, data in st.session_state.encrypted_transactions.items()})
