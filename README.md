IT-Sicherheit PGP-Schlüssel-Server
==================================

Dieses Projekt ist ein Server, der die Erstellung, Registrierung und Verwaltung von PGP-Schlüsseln ermöglicht. Der Server bietet RESTful API-Endpunkte für die folgenden Aktionen:

* Kontoerstellung
* Schlüsselgenerierung
* Schlüsselregistrierung
* Antwort auf eine Challenge
* Nachrichtenverschlüsselung
* Nachrichtenentschlüsselung

Anforderungen
------------

* Python 3.x
* Flask
* Flask-HTTPAuth
* PyGPGME

Installation
------------

1. Klonen Sie das Repository:
```bash
git clone https://github.com/htsago/IT-sicherheit.git
```
oder 
```bash
git clone git@github.com:htsago/IT-sicherheit.git
```
1. Navigieren Sie zum Projektverzeichnis:
```bash
cd IT-Sicherheit
```
1. Erstellen Sie eine virtuelle Umgebung (optional, aber empfohlen):
```bash
python3 -m venv venv
```
1. Aktivieren Sie die virtuelle Umgebung:
```bash
source venv/bin/activate
```
1. Installieren Sie die erforderlichen Pakete:
```bash
pip install -r requirements.txt
```
1. Starten Sie den Server:
```bash
python challenge.py
```
Der Server läuft standardmäßig auf `http://127.0.0.1:5000`.

Verwendung
-----------

### Kontoerstellung

Erstellen Sie ein neues Konto, indem Sie eine `POST`-Anfrage an den Endpunkt `/create-account` senden. Der Anfragetext muss im JSON-Format sein und die Felder `account-id` und `password` enthalten:

```json
{
    "account-id": "Ihre E-Mail-Adresse",
    "password": "Ihr Passwort"
}
```

Sie können die Anfrage mit `curl` senden:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"account-id": "Ihre E-Mail-Adresse", "password": "Ihr Passwort"}' http://127.0.0.1:5000/create-account
```

### Schlüsselgenerierung

Generieren Sie ein neues PGP-Schlüsselpaar, indem Sie eine `POST`-Anfrage an den Endpunkt `/generate-keys` senden. Der Anfragetext muss im JSON-Format sein und das Feld `email-addresse` enthalten:

```json
{
    "email-addresse": "Ihre E-Mail-Adresse"
}
```

Sie können die Anfrage mit `curl` senden:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"email-addresse": "Ihre E-Mail-Adresse"}' http://127.0.0.1:5000/generate-keys
```

Der öffentliche und der private Schlüssel werden an die angegebene E-Mail-Adresse gesendet.

### Schlüsselregistrierung

Registrieren Sie einen öffentlichen PGP-Schlüssel, indem Sie eine `POST`-Anfrage an den Endpunkt `/register-key` senden. Fügen Sie die folgenden Felder in das Formular ein:

* `email-adresse`: Die E-Mail-Adresse, an die der Schlüssel gesendet wurde.
* `key-id`: Die Key-ID des öffentlichen Schlüssels.
* `public_key_file`: Die Datei mit dem öffentlichen Schlüssel.

Sie müssen sich mit Ihrer Konten-ID und Ihrem Passwort authentifizieren, um die Anfrage zu senden. Sie können die Anfrage mit `curl` senden:

```bash
curl -X POST -F "email-adresse=Ihre E-Mail-Adresse" -F "key-id=Ihre Key-ID" -F "public_key_file=@/Pfad/zur/Datei/mit/dem/öffentlichen/Schlüssel" http://127.0.0.1:5000/register-key
```

Nach der Registrierung erhalten Sie eine Challenge-E-Mail. Antworten Sie auf diese E-Mail, um Ihren Schlüssel signieren zu lassen.

### Antwort auf eine Challenge

Antworten Sie auf eine Challenge, indem Sie eine `POST`-Anfrage an den Endpunkt `/response` senden. Fügen Sie die folgenden Felder in das Formular ein:

* `email-adresse`: Die E-Mail-Adresse, an die der Schlüssel gesendet wurde.
* `response`: Die Antwort auf die Challenge.

Sie müssen sich mit Ihrer Konten-ID und Ihrem Passwort authentifizieren, um die Anfrage zu senden. Sie können die Anfrage mit `curl` senden:

```bash
 curl -X POST   http://localhost:5000/response   -u account_id:passwort   -F 'email-adresse=your email-adress'   -F 'response=Antwort auf Challenge'
```

### Nachrichtenverschlüsselung

Verschlüsseln Sie eine Nachricht, indem Sie eine `POST`-Anfrage an den Endpunkt `/encrypt-message` senden. Der Anfragetext muss im JSON-Format sein und die Felder `recipient-email` und `message-text` enthalten:

```json
{
    "recipient-email": "E-Mail-Adresse des Empfängers",
    "message-text": "Ihre Nachricht"
}
```

Sie müssen sich mit Ihrer Konten-ID und Ihrem Passwort authentifizieren, um die Anfrage zu senden. Sie können die Anfrage mit `curl` senden:

```bash
 curl -X POST   http://localhost:5000/encrypt-message   -u account_id:passwort   -H "Content-Type: application/json"   -d '{
    "recipient-email": "email vom Empfänger",
    "message-text": "die zu verschlüsselne Message."
}'
```

Die verschlüsselte Nachricht wird als `.asc`-Datei zurückgegeben.

### Nachrichtenentschlüsselung

Entschlüsseln Sie eine Nachricht, indem Sie eine `POST`-Anfrage an den Endpunkt `/decrypt-message` senden. Fügen Sie die folgenden Felder in das Formular ein:

* `private-key`: Die Datei mit Ihrem privaten Schlüssel.
* `encrypted-file`: Die Datei mit der verschlüsselten Nachricht.

Sie müssen sich mit Ihrer Konten-ID und Ihrem Passwort authentifizieren, um die Anfrage zu senden. Sie können die Anfrage mit `curl` senden:

```bash
curl -X POST   http://localhost:5000/decrypt-message   -u account_id:passwort   -F 'private-key=@/home/htsago/IT-sicherheit/keys/private.asc'   -F 'encrypted-file=@/pfad/to/IT-sicherheit/keys/encrypted_message.asc'
```

Die entschlüsselte Nachricht wird im JSON-Format zurückgegeben:

```json
{
    "decrypted-message": "Ihre entschlüsselte Nachricht"
}
```

Hinweis: Stellen Sie sicher, dass Sie Ihren privaten Schlüssel sicher aufbewahren und ihn niemandem weitergeben.

Autoren
-------

* [Herman Tsago]
* [Fode Abass Camara]
