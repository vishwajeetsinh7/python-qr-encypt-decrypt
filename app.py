from flask import Flask, render_template, request, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad  
from Crypto.Protocol.KDF import PBKDF2
import base64
import os

app = Flask(__name__)

WEBSITE_URL = "http://127.0.0.1:5000/"

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        message = request.form['message']
        password = request.form['password']

        salt = os.urandom(16)
        key = PBKDF2(password, salt, dkLen=32)
        padded_message = pad(message.encode(), AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, salt)
        ct_bytes = cipher.encrypt(padded_message)
        iv = cipher.iv

        encoded_data = iv + salt + ct_bytes
        decryption_url = url_for('decrypt')  # Use url_for to get the route URL
        qr_image = generate_qr_code(decryption_url, encoded_data)

        return render_template('home.html', qr_image=qr_image, website_name=WEBSITE_URL, encrypted_data=encoded_data.hex())



    return render_template('home.html', website_name=WEBSITE_URL)

@app.route('/redirect', methods=['GET'])
def redirect_to_website():
    return redirect(url_for('home'), code=302)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'GET':
        encrypted_data_hex = request.args.get('encrypted_data', '')
        return render_template('decrypt_form.html', encrypted_data=encrypted_data_hex)
    elif request.method == 'POST':
        encrypted_data_hex = request.form['encrypted_data']
        password = request.form['password']

        encrypted_data = bytes.fromhex(encrypted_data_hex)
        iv = encrypted_data[:16]
        salt = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        key = PBKDF2(password, salt, dkLen=32)

        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
            return render_template('decrypted.html', decrypted_message=decrypted_message)
        except ValueError:
            error_message = "Wrong password entered. Please try again."
            return render_template('decrypt_form.html', error_message=error_message)

def generate_qr_code(decryption_url, encoded_data):
    import qrcode
    from io import BytesIO

    qr = qrcode.make(f"{decryption_url}?encrypted_data={encoded_data.hex()}")
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_image = base64.b64encode(buffered.getvalue()).decode('utf-8')
    return qr_image

if __name__ == '__main__':
    app.run(debug=False)
