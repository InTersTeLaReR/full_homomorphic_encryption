#for sit hackathon by team codesmith
import random
import smtplib
from email.message import EmailMessage
import subprocess  


otp = ""
for i in range(6):
    otp += str(random.randint(0, 9))

#i have removed my password and email so make sure to add urs in this place- by team codesmith
from_mail = 'email@gmail.com' 
password = 'passwaord' 

try:

    server = smtplib.SMTP('smtp.gmail.com', 587) 
    server.starttls() 
    server.login(from_mail, password)  

   
    to_mail = input("Enter the recipient's email: ")

    
    msg = EmailMessage()
    msg['Subject'] = "OTP VERIFICATION"
    msg['From'] = from_mail
    msg['To'] = to_mail
    msg.set_content(f"Your OTP is: {otp}")

    
    server.send_message(msg)
    print("OTP sent successfully!")

  
    input_otp = input("Enter the OTP: ")

   
    if input_otp == otp:
        print("OTP is verified!")
        
        
        print('streamlit run finance_app.py')
        
       
        subprocess.Popen(['streamlit', 'run', 'finance_app.py']) 
    else:
        print("Invalid OTP")

except Exception as e:
    print(f"Error sending email: {e}")

finally:
    server.quit()  
