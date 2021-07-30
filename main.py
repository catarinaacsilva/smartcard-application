# coding: utf-8


import base64
from flask import Flask, request, jsonify
from pteid import PortugueseCitizenCard
from flask_cors import CORS


app = Flask(__name__)
CORS(app)


@app.route('/sign', methods=['GET'])
def sign():
    data = request.args.get('data')
    print(data)
    data = base64.urlsafe_b64decode(data).decode('UTF-8')
    print(data)
    pteid = PortugueseCitizenCard()
    if len(pteid.sessions) > 0:
        pteid.login(0)
        signedData = pteid.sign_data(0, data)
        encoded_signedData = base64.urlsafe_b64encode(signedData)
        cert = pteid.PTEID_GetCertificate(0)
        encoded_cert = base64.urlsafe_b64encode(cert)
        pteid.logout(0)
        pteid.sessions[0].closeSession()
        return jsonify({'signedReceipt': encoded_signedData.decode('UTF-8'), 'cert': encoded_cert.decode('UTF-8')})
    return jsonify({'error': 'Card not found'})

@app.route('/verify', methods=['GET'])
def verify():
    data = request.args.get('data')
    signedData = request.args.get('signedData')
    pteid = PortugueseCitizenCard()
    if len(pteid.sessions) > 0:
        pteid.login(0)
        verified = False
        decoded = signedData.encode('UTF-8')
        decoded_bytes = base64.urlsafe_b64decode(decoded)
        if (pteid.verifySignature(pteid.PTEID_GetCertificate(0), data, decoded_bytes)): 
            verified = True
        pteid.logout(0)
        pteid.sessions[0].closeSession()
        return jsonify({'verify': verified})
    return jsonify({'error': 'Card not found'})

if __name__ == '__main__':
    app.run(host='localhost', port=8686, debug=False)
