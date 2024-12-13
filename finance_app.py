import streamlit as st
from phe import paillier

# Generate public and private keys (only once per session)
if "public_key" not in st.session_state:
    public_key, private_key = paillier.generate_paillier_keypair()
    st.session_state.public_key = public_key
    st.session_state.private_key = private_key

# Initialize session state for storing encrypted data
if "encrypted_transactions" not in st.session_state:
    st.session_state.encrypted_transactions = {}

# Function to encrypt data
def encrypt_data(data):
    encrypted_data = st.session_state.public_key.encrypt(float(data))
    return encrypted_data

# Function to decrypt data
def decrypt_data(encrypted_data):
    return st.session_state.private_key.decrypt(encrypted_data)

# Sidebar Navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to:", ["User Section", "Admin Section"])

# User Section
if page == "User Section":
    st.title("Secure Financial Data Submission")

    # User inputs financial data
    st.header("Submit Financial Data")
    user_id = st.text_input("Enter User ID:")
    transaction_amount = st.text_input("Enter Transaction Amount (numeric):")

    if st.button("Encrypt and Submit"):
        if user_id and transaction_amount.replace('.', '', 1).isdigit():
            # Encrypt and store data in session state
            encrypted_data = encrypt_data(transaction_amount)
            st.session_state.encrypted_transactions[user_id] = encrypted_data
            st.success("Transaction encrypted and stored securely!")
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
