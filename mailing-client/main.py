import smptlib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

server = smtplib.SMTP('smtp.gmail.com', 25) # SMTP server and port
server.ehlo() # Say hello to the server
server.login('sender@gmail.com', 'password123') # your email and password

msg = MIMEMultipart()
msg['From'] = 'lumin3t'
msg['To'] = 'reciever@example.com' # recipient email
msg['Subject'] = 'This mail was sent using python!'
with open('message.txt', 'r') as file:
    message = file.read()
msg.attach(MIMEText(message, 'plain'))
