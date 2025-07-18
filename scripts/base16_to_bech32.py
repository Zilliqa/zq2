# Before running the script, please make sure you have the dependencies installed:
# pip install flask bech32
#
# Usage:
#
# curl -X POST http://127.0.0.1:5000/convert \
#   -H "Content-Type: application/json" \
#   -d '{"zil_address": "zil1f42xpqztl9zt0j24gqda8ypdg2a8ja0fmg4p2a"}'
# curl -X POST http://127.0.0.1:5000/convert \
#   -H "Content-Type: application/json" \
#   -d '{"evm_address": "0x4cb8d0a035f36fcdeede0b92769d70d577ff89b3"}'


from flask import Flask, request, jsonify
from bech32 import bech32_decode, bech32_encode, convertbits

app = Flask(__name__)

def zil_to_evm(zil_address):
    try:
        hrp, data = bech32_decode(zil_address)
        if hrp != 'zil' or data is None:
            return None
        decoded_bytes = convertbits(data, 5, 8, False)
        if not decoded_bytes or len(decoded_bytes) != 20:
            return None
        return '0x' + ''.join(f'{b:02x}' for b in decoded_bytes)
    except Exception:
        return None

def evm_to_zil(evm_address):
    try:
        if evm_address.startswith("0x"):
            evm_address = evm_address[2:]
        if len(evm_address) != 40:
            return None
        bytes_addr = bytes.fromhex(evm_address)
        data = convertbits(list(bytes_addr), 8, 5)
        if not data:
            return None
        return bech32_encode('zil', data)
    except Exception:
        return None

@app.route('/convert', methods=['POST'])
def convert():
    data = request.get_json()
    zil = data.get('zil_address')
    evm = data.get('evm_address')

    if zil:
        evm_result = zil_to_evm(zil)
        if not evm_result:
            return jsonify({"error": "Invalid Zilliqa address"}), 400
        return jsonify({"evm_address": evm_result})

    elif evm:
        zil_result = evm_to_zil(evm)
        if not zil_result:
            return jsonify({"error": "Invalid EVM address"}), 400
        return jsonify({"zil_address": zil_result})

    else:
        return jsonify({"error": "Must provide either zil_address or evm_address"}), 400

if __name__ == '__main__':
    app.run(debug=True)
