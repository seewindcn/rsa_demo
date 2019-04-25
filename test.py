# -*- coding: utf-8 -*-

import sys
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS, PKCS1_v1_5
from Crypto.Hash import SHA256, SHA512


def get_public_key():
    with open('key/id_rsa.pub') as f:
        return f.read()


def get_pri_key():
    with open('key/id_rsa') as f:
        return f.read()


def verify(sign, plain_data, test=False, encoding='utf-8'):
    try:
        if isinstance(plain_data, str):
            plain_data = plain_data.encode(encoding)
        sign = base64.b64decode(sign)

        hash = SHA256.new(plain_data)
        key = RSA.importKey(get_public_key())
        verifier = PKCS1_PSS.new(key)
        # verifier = PKCS1_v1_5.new(key)
        if not test:
            return verifier.verify(hash, sign)
        return hash.hexdigest(), verifier.verify(hash, sign)
    except Exception as err:
        if settings.DEBUG:
            logger.info('verify error:%s', err)
        if not test:
            return False
        return None, False


def sign(plain_data, test=False, encoding='utf-8'):
    """
    plain_data is utf-8 encoding
    base64(rsa_sign(hash(plain_data)))
    """
    if isinstance(plain_data, str):
        plain_data = plain_data.encode(encoding)
    key = RSA.importKey(get_pri_key())
    signer = PKCS1_PSS.new(key)
    hash = SHA256.new(plain_data)
    sign = base64.b64encode(signer.sign(hash)).decode()
    if not test:
        return sign
    return hash.hexdigest(), sign


def test():
    if len(sys.argv) == 3:
        data, sign_data = sys.argv[1], sys.argv[2]
        hash, ok = verify(sign_data, data, test=True)
    else:
        data = 'abc'
        hash, sign_data = sign(data, test=True)
        print('sign: ', sign_data)
        ok = verify(sign_data, data)
    print('hash: ', hash, ok)


if __name__ == '__main__':
    test()


