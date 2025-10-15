import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

server = smtplib.SMTP('smtp.gmail.com', 587) # SMTP server and port, 25 SMTP 587 is secure version
server.starttls() 
server.ehlo() # Say hello to the server
with open('password.txt', 'r') as file:
    password = file.read().strip()
server.login('<sender>@gmail.com', password) # your email and password

msg = MIMEMultipart()
msg['From'] = 'lumin3t'
msg['To'] = '<reciever>@<example>.com' # recipient email
msg['Subject'] = 'This mail was sent using python!'
with open('message.txt', 'r') as file:
    message = file.read()

msg.attach(MIMEText(message, 'plain'))

filename = 'hehe.jpg' # file to be attached
attachment = open(filename, 'rb') # open the file in binary mode cuz image data and not text data

p = MIMEBase('application', 'octet-stream') # stream we are using to process image data 
p.set_payload(attachment.read()) 

encoders.encode_base64(p)
p.add_header('Content-Disposition', f'attachment; filename={filename}')
msg.attach(p)

text = msg.as_string()
server.sendmail('<sender>@gmail.com', '<reciever>@<example>.com', text)
