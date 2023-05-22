import smtplib

sender_email = "hung@siit.tu.ac.th"  # Enter your address
receiver_email = "hung@siit.tu.ac.th"  # Enter receiver address
password = "xxxxxxxxx"

# creates SMTP session
s = smtplib.SMTP('smtp.gmail.com', 587)

# start TLS for security
s.starttls()

# Authentication
s.login(sender_email, password)

# message to be sent
message = "Message_you_need_to_send"

# sending the mail
s.sendmail(sender_email, receiver_email, message)

# terminating the session
s.quit()
