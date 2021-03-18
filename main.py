# coding: utf-8


import base64
from flask import Flask, request, jsonify
from pteid import PortugueseCitizenCard

app = Flask(__name__)


@app.route('/sign', methods=['GET'])
def sign():
    data = request.args.get('data')
    pteid = PortugueseCitizenCard()
    if len(pteid.sessions) > 0:
        pteid.login(0)
        signedData = pteid.sign_data(0, data)
        return jsonify({'signedReceipt': base64.b64encode(signedData).decode('UTF-8')})
    return jsonify({'error': 'Card not found'})



if __name__ == '__main__':
    app.run(host='localhost', port=8686, debug=False)
