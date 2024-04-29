from flask import Flask, request, jsonify,render_template
import json
import os
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
import smtplib
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from flask import send_file
import io
import hashlib
from werkzeug.utils import secure_filename
import os
from flask_httpauth import HTTPBasicAuth


auth = HTTPBasicAuth()
app = Flask(__name__)

@auth.verify_password
def verify_password(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if username in users and users[username]['password'] == hashed_password:
        return username


@auth.error_handler
def unauthorized():
    return jsonify({"error": "Unauthorisierter Zugriff"}), 401

# Pfade für JSON-Dateien
register_file = '/home/htsago/IT-sicherheit/bin/scripts/data/register.json'
users_file = "/home/htsago/IT-sicherheit/bin/scripts/data/users.json"
os.makedirs('keys', exist_ok=True)

# Lade vorhandene Daten
if os.path.exists(users_file):
    with open(users_file, 'r') as f:
        users = json.load(f)
else:
    users = {}

if os.path.exists(register_file):
    with open(register_file, 'r') as f:
        register = json.load(f)
else:
    register = {}

def save_json_data(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def add_user_for_create(account_id, hashed_password):
    user_data = {
        'password': hashed_password,
    }
    users[account_id] = user_data
    save_json_data(users, users_file)

def add_user_for_register(account_id, public_key, private_key, fingerprint):
    if account_id in register:
        register[account_id].update({
            'public_key': public_key,
            'private_key': private_key,  
            'fingerprint': fingerprint,
            'key_id': fingerprint[-16:]
        })
        save_json_data(register, register_file)
    else:
        logger.error(f"Benutzerkonto {account_id} existiert nicht.")

def generate_pgp_key(account_id):
    user_key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(account_id, comment="Benutzer PGP Schlüssel")
    user_key.add_uid(uid, self_sign=True, primary=True,
                     usage={KeyFlags.EncryptCommunications, KeyFlags.Sign},
                     hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384,
                             HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                     ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192,
                              SymmetricKeyAlgorithm.AES128],
                     compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2,
                                  CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

    ascii_armored_public_key = str(user_key.pubkey).encode('utf-8')
    ascii_armored_private_key = str(user_key).encode('utf-8')
    
    fingerprint = str(user_key.fingerprint)
    key_id = fingerprint[-16:] 

    return ascii_armored_public_key, ascii_armored_private_key, fingerprint, key_id

def EmailContents(from_email, to_email, subject, body):
    message = MIMEMultipart()
    message['From'] = from_email
    message['To'] = to_email
    message['Subject'] = subject
    message['Date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    message.attach(MIMEText(body, 'plain'))

    return message



def send_challenge(email_address, key_id):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "team25itsec@gmail.com"
    smtp_password = "hjvf zsdv evvp yodo"
    subject = "PGP Schlüsselbestätigung"
    challenge_message = f"Lieber Benutzer, bitte antworten Sie auf diese E-Mail mit Ihrer Key-ID: {key_id}."

    message = EmailContents(smtp_username, email_address, subject, challenge_message)

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_username, smtp_password)
    server.sendmail(smtp_username, email_address, message.as_string())
    server.quit()

def send_signed_key(email_address):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "team25itsec@gmail.com"
    smtp_password = "hjvf zsdv evvp yodo"
    subject = "Ihr signierter PGP-Schlüssel"
    body = "Hier ist Ihr signierter PGP-Schlüssel im Anhang."

    message = EmailContents(smtp_username, email_address, subject, body)

    # Laden des privaten Schlüssels des Servers und Signieren des Fingerabdrucks
    server_private_key, _ = pgpy.PGPKey.from_file('/home/htsago/IT-sicherheit/keys/private_server.asc')
    fingerprint = register[email_address]['fingerprint']

    # Signieren des Fingerabdrucks
    signature = server_private_key.sign(fingerprint)

    print(signature)
    # Hinzufügen der signierten Fingerabdruck-Signatur als Text
    message.attach(MIMEText(str(signature), 'plain'))

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_username, smtp_password)
    server.sendmail(smtp_username, email_address, message.as_string())
    server.quit()

def send_email_with_key(recipient_email, public_key,private_key, key_id):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "team25itsec@gmail.com"
    smtp_password = "hjvf zsdv evvp yodo" 
    from_email = "team25itsec@gmail.com"
    subject = "Ihr PGP-Schlüssel"
    body = f"Ihre Key-ID ist: {key_id}"

    message = EmailContents(from_email, recipient_email, subject, body)

    # Anhängen des öffentlichen Schlüssels
    part_public = MIMEBase('application', 'octet-stream')
    part_public.set_payload(public_key)
    encoders.encode_base64(part_public)
    part_public.add_header('Content-Disposition', f'attachment; filename="public.asc"')
    message.attach(part_public)

    # Anhängen des privaten Schlüssels
    part_private = MIMEBase('application', 'octet-stream')
    part_private.set_payload(private_key)
    encoders.encode_base64(part_private)
    part_private.add_header('Content-Disposition', f'attachment; filename="private.asc"')
    message.attach(part_private)

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_username, smtp_password)
    server.sendmail(from_email, recipient_email, message.as_string())
    server.quit()

@auth.login_required
@app.route('/generate-keys', methods=['POST'])
def generatekey():
    data = request.json
    email_address = data.get('email-addresse')

    if not email_address:
        return jsonify({"error": "E-Mail-Adresse fehlt"}), 400

    ascii_armored_public_key, ascii_armored_private_key, fingerprint, key_id = generate_pgp_key(email_address)

    register[email_address] = {
        'public_key': ascii_armored_public_key.decode('utf-8'),
        'fingerprint': fingerprint,
        'key_id': key_id
    }
    save_json_data(register, register_file)
    try:
        send_email_with_key(email_address, ascii_armored_public_key, ascii_armored_private_key, key_id)
        success_message = {'message': 'Schlüsselpaar generiert, registriert und E-Mail gesendet'}
    except Exception as e:
        success_message = {'message': 'Schlüsselpaar generiert und registriert, aber E-Mail-Fehler: ' + str(e)}

    return jsonify(success_message), 200

@auth.login_required
@app.route('/create-account', methods=['POST'])
def create_account():
    data = request.json
    account_id = data.get('account-id')
    password = data.get('password')

    if not all([account_id, password]):
        return jsonify({"error": "Es fehlen erforderliche Daten"}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if account_id in users:
        return jsonify({"error": "Benutzer existiert bereits"}), 400

    add_user_for_create(account_id, hashed_password)

    return jsonify({"message": "Konto erfolgreich erstellt", "account-id": account_id}), 200

@auth.login_required
@app.route('/register-key', methods=['POST'])
def register_key():
    email_address = request.form.get('email-adresse')
    user_provided_key_id = request.form.get('key-id')
    public_key_file = request.files.get('public_key_file')
    password = request.authorization.password  
    if not email_address or not user_provided_key_id or not public_key_file or not password:
        return jsonify({"error": "Erforderliche Daten fehlen"}), 400

    # Überprüfe, ob das vom Benutzer angegebene Passwort korrekt ist
    if not verify_password(request.authorization.username, password):
        return jsonify({"error": "Falsches Passwort"}), 401

    public_key_data = public_key_file.read().decode('utf-8')
    try:
        public_key, _ = pgpy.PGPKey.from_blob(public_key_data)
        fingerprint = str(public_key.fingerprint)
        derived_key_id = fingerprint[-16:]
    except Exception as e:
        return jsonify({"error": f"Fehler beim Lesen des öffentlichen Schlüssels: {str(e)}"}), 400
    if user_provided_key_id != derived_key_id:
        return jsonify({"error": "Die angegebene Key-ID stimmt nicht mit dem öffentlichen Schlüssel überein"}), 400
    if email_address in register or any(user['key_id'] == user_provided_key_id for user in register.values()):
        return jsonify({"error": "E-Mail-Adresse oder Key-ID bereits registriert"}), 409

    register[email_address] = {
        'public_key': public_key_data,
        'key_id': user_provided_key_id,
        'fingerprint': fingerprint
    }
    save_json_data(register, register_file)
    send_challenge(email_address, user_provided_key_id)
    return jsonify({"message": "Challenge gesendet."}), 200


@auth.login_required
@app.route('/response', methods=['POST'])
def response():
    email_address = request.form.get('email-adresse')
    account_id = request.authorization.username
    password = request.authorization.password
    
    # Überprüfe, ob das vom Benutzer angegebene Passwort korrekt ist
    if not verify_password(account_id, password):
        return jsonify({"error": "Falsches Passwort"}), 401
    
    # Überprüfe, ob die E-Mail-Adresse im Register vorhanden ist
    if email_address in register:
        user_response = request.form.get('response')
        expected_response = f"{register[email_address]['key_id']}"
        if user_response == expected_response:
            send_signed_key(email_address)
            return jsonify({"message": "Schlüssel signiert und gesendet"}), 200
        else:
            return jsonify({"error": "Falsche Antwort auf die Challenge"}), 400
    else:
        # Wenn die E-Mail-Adresse nicht im Register vorhanden ist
        return jsonify({"error": "E-Mail-Adresse nicht gefunden"}), 404

def encrypt_message(recipient_public_key_data, message_text):
    recipient_key, _ = pgpy.PGPKey.from_blob(recipient_public_key_data)
    message = pgpy.PGPMessage.new(message_text)
    encrypted_message = recipient_key.encrypt(message)
    return str(encrypted_message)

def decrypt_message(private_key, encrypted_message):
    private_key, _ = pgpy.PGPKey.from_blob(private_key)
    encrypted_message = pgpy.PGPMessage.from_blob(encrypted_message)
    decrypted_message = private_key.decrypt(encrypted_message)
    return decrypted_message.message

@auth.login_required
@app.route('/encrypt-message', methods=['POST'])
def encrypt_message_route():
    data = request.json
    recipient_email = data.get('recipient-email')
    message_text = data.get('message-text')
    password = request.authorization.password
    account_id = request.authorization.username

    if not recipient_email or not message_text or not password or not account_id:
        return jsonify({"error": "Erforderliche Daten fehlen"}), 400

    # Überprüfe, ob das vom Benutzer angegebene Passwort korrekt ist
    if not verify_password(account_id, password):
        return jsonify({"error": "Falsches Passwort"}), 401

    if recipient_email not in register:
        return jsonify({"error": "Empfänger nicht gefunden"}), 404

    recipient_public_key_data = register[recipient_email]['public_key']
    encrypted_message = encrypt_message(recipient_public_key_data, message_text)

    # Speichere die verschlüsselte Nachricht vorübergehend in einer Datei
    encrypted_file_path = "/home/htsago/IT-sicherheit/keys/encrypted_message.asc"
    with open(encrypted_file_path, 'w') as encrypted_file:
        encrypted_file.write(encrypted_message)

    # Sende die verschlüsselte Nachricht als .asc-Datei zurück
    return send_file(encrypted_file_path, as_attachment=True)

@auth.login_required
@app.route('/decrypt-message', methods=['POST'])
def decrypt_message_route():
    private_key_file = request.files.get('private-key')
    encrypted_file = request.files.get('encrypted-file')
    password = request.authorization.password
    account_id = request.authorization.username

    if not private_key_file or not encrypted_file or not password or not account_id:
        return jsonify({"error": "Erforderliche Daten fehlen"}), 400

    # Überprüfe, ob das vom Benutzer angegebene Passwort korrekt ist
    if not verify_password(account_id, password):
        return jsonify({"error": "Falsches Passwort"}), 401

    private_key_data = private_key_file.read().decode('utf-8')
    encrypted_message = encrypted_file.read().decode('utf-8')

    try:
        decrypted_message = decrypt_message(private_key_data, encrypted_message)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"decrypted-message": decrypted_message}), 200

if __name__ == '__main__':
    app.run(debug=True)
