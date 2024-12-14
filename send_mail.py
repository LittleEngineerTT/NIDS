import gnupg
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def send_encrypted_email(asc_cert_path, recipient_email, sender_email, smtp_password, subject, message):
    try:
        gpg = gnupg.GPG()
        import_result = gpg.import_keys_file(asc_cert_path)
        if not import_result.fingerprints:
            raise Exception("No valid certificate imported")

        fingerprint = import_result.fingerprints[0]
        keys = gpg.list_keys()
        if not any(key['fingerprint'] == fingerprint for key in keys):
            raise Exception("Imported certificate not found in keyring")

        encrypted_data = gpg.encrypt(message, fingerprint, always_trust=True)
        if not encrypted_data.ok:
            raise Exception(f"Encryption failed: {encrypted_data.status}")

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(str(encrypted_data), 'plain'))

        smtp_server = "smtp.gmail.com"  # Exemple avec Gmail
        smtp_port = 587
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, smtp_password)
        server.send_message(msg)
        server.quit()
        return True

    except Exception as e:
        print(str(e))
        return False
