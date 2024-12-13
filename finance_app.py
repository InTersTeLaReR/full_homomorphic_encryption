import streamlit as st
from phe import paillier
import time

if "public_key" not in st.session_state:
    public_key, private_key = paillier.generate_paillier_keypair()
    st.session_state.public_key = public_key
    st.session_state.private_key = private_key

# Initialize session state for storing encrypted data
if "encrypted_transactions" not in st.session_state:
    st.session_state.encrypted_transactions = {}

# Initialize session state for passkey change logic
if "last_passkey_change_time" not in st.session_state:
    st.session_state.last_passkey_change_time = time.time()  # Store the timestamp of the last passkey change

# Function to encrypt data
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

st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to:", ["User Section", "Admin Section"])

# User Section
if page == "User Section":
    st.title("Secure Financial Data Submission")

    # User inputs financial data
    st.header("Submit Financial Data")
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
elif page == "Admin Section":
    st.title("Admin Panel")

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

# Optional: Display encrypted data storage for demonstration
st.sidebar.header("Encrypted Data Overview")
# Convert encrypted data to a string for JSON display
st.sidebar.json({user: {"ciphertext": str(data.ciphertext()), "exponent": data.exponent} for user, data in st.session_state.encrypted_transactions.items()})
