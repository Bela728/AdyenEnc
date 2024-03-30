from datetime import datetime
from os import urandom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import pytz
import json
import base64


class encryptor:
    def __init__(self, adyen_public_key, adyen_version='_0_1_8', adyen_prefix='adyenjs'):
        """
        :param adyen_public_key: adyen key, looks like this: "10001|A2370..."
        :param adyen_version: version of adyen encryption, looks like this: _0_1_8
        :param adyen_prefix: prefix before adyen version. can vary depending on where you are submitting the payment. typically is just "adyenjs"
        """

        self.adyen_public_key = adyen_public_key
        self.adyen_version = adyen_version
        self.adyen_prefix = adyen_prefix

    def encrypt_field(self, name: str, value: str):
        """
        :param name: name of field you want to encrypt, for ex, "cvc"
        :param value: value of the field you want to encrypt
        :return: a string containing the adyen-encrypted field
        """

        plain_card_data = self.field_data(name, value)
        card_data_json_string = json.dumps(plain_card_data, sort_keys=True)

        # Encrypt the actual card data with symmetric encryption
        aes_key = self.generate_aes_key()
        nonce = self.generate_nonce()
        encrypted_card_data = self.encrypt_with_aes_key(aes_key, nonce, bytes(card_data_json_string, encoding='utf-8'))
        encrypted_card_component = nonce + encrypted_card_data

        # Encrypt the AES Key with asymmetric encryption
        public_key = self.decode_adyen_public_key(self.adyen_public_key)
        encrypted_aes_key = self.encrypt_with_public_key(public_key, aes_key)

        return "{}{}${}${}".format(self.adyen_prefix,
                                   self.adyen_version,
                                   base64.standard_b64encode(encrypted_aes_key).decode(),
                                   base64.standard_b64encode(encrypted_card_component).decode())

    def encrypt_card(self, card: str, cvv: str, month: str, year: str):
        """
        :param card: card number string
        :param cvv: cvv number string
        :param month: card month string
        :param year: card year string
        :return: dictionary with all encrypted card fields (card, cvv, month, year)
        """

        data = {
            'card': self.encrypt_field('number', card),
            'cvv': self.encrypt_field('cvc', cvv),
            'month': self.encrypt_field('expiryMonth', month),
            'year': self.encrypt_field('expiryYear', year),
        }

        return data

    def field_data(self, name, value):
        """
        :param name: name of field
        :param value: value of field
        :return: a dict to be encrypted
        """

        generation_time = datetime.now(tz=pytz.timezone('UTC')).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        field_data_json = {
            name: value,
            "generationtime": generation_time
        }

        return field_data_json

    def encrypt_from_dict(self, dict_: dict):
        plain_card_data = dict_
        card_data_json_string = json.dumps(plain_card_data, sort_keys=True)

        # Encrypt the actual card data with symmetric encryption
        aes_key = self.generate_aes_key()
        nonce = self.generate_nonce()
        encrypted_card_data = self.encrypt_with_aes_key(aes_key, nonce, bytes(card_data_json_string, encoding='utf-8'))
        encrypted_card_component = nonce + encrypted_card_data

        # Encrypt the AES Key with asymmetric encryption
        public_key = self.decode_adyen_public_key(self.adyen_public_key)
        encrypted_aes_key = self.encrypt_with_public_key(public_key, aes_key)

        return "{}{}${}${}".format(self.adyen_prefix,
                                   self.adyen_version,
                                   base64.standard_b64encode(encrypted_aes_key).decode(),
                                   base64.standard_b64encode(encrypted_card_component).decode())

    @staticmethod
    def decode_adyen_public_key(encoded_public_key):
        backend = default_backend()
        key_components = encoded_public_key.split("|")
        public_number = rsa.RSAPublicNumbers(int(key_components[0], 16), int(key_components[1], 16))
        return backend.load_rsa_public_numbers(public_number)

    @staticmethod
    def encrypt_with_public_key(public_key, plaintext):
        ciphertext = public_key.encrypt(plaintext, padding.PKCS1v15())
        return ciphertext

    @staticmethod
    def generate_aes_key():
        return AESCCM.generate_key(256)

    @staticmethod
    def encrypt_with_aes_key(aes_key, nonce, plaintext):
        cipher = AESCCM(aes_key, tag_length=8)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return ciphertext

    @staticmethod
    def generate_nonce():
        return urandom(12)
    
    
    
    
def adyen_enc(cc, mes, ano, cvv, ADYEN_KEY, adyen_version):
    enc = encryptor(ADYEN_KEY)
    enc.adyen_version = adyen_version
    enc.adyen_public_key = ADYEN_KEY

    card = enc.encrypt_card(card=cc, cvv=cvv, month=mes, year=ano)
    month = card['month']
    year = card['year']
    cvv = card['cvv']
    card = card['card']


    return card, month, year,cvv
# print(adyen_enc('4403932515225299','05','2025','021','10001|8C37AA911BD0D55F3DFE074079E9DF328CE8CAB704370AA6985CE8C1CD67309C5365A0FE49B03546DC64B50AE171369635B70EE86C7DD162A984E0633553608E4511086ADB41318E7D9967EC5FE3AAE245530A6C88178B3629C7412F2D0FADDAE4663497DE6D0C765355F6CD0F3E2582495285DF97B1CF0A58816267C55E47588FF228818F84B668647CB5A1E953319C204C98B0EE83BC384544B10ACB0BD1352B2C3E3CDBAB6EE55AAE0358AAF24A403CEB41BE31D923D3CF721F8B3E380E31CEED00678555169F0B1E9B4EF95CC6A9E1C101D554E0D4ADB06B855F28DD523DD16110AB708D2FD4ED120EEEF23D17B55E93EDAA1A595BB54882AB3A9C2ED43D','_0_1_25'))

from fastapi import FastAPI
from fastapi import FastAPI, HTTPException
from fastapi import FastAPI, Request
from fastapi.responses  import RedirectResponse
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import json


class UnicornException(Exception):
    def __init__(self, name: str,  message: str):
        self.name = name
        self.message = message


app = FastAPI(debug=True, 
              title="Bin lookup And Adyen Generator By .", 
              redoc_url=None,
              description=" Feel free to use. made by for subscribers.")

@app.exception_handler(UnicornException)
async def unicorn_exception_handler(request: Request, exc: UnicornException):
    return JSONResponse(
        status_code=418,
        content={'success': False, "message": exc.message},
    )




class Item(BaseModel):
    card: str
    month: str
    year: str
    cvv: str
    adyen_version: str
    adyen_key: str

@app.get("/")
async def start():
    return RedirectResponse("http://www.github.com/r0ld3x/adyen-enc-and-bin-info")


@app.post("/adyen/")
async def adyen(item: Item):
    cc, mes, ano, cvv = adyen_enc(
        item.card, item.month, item.year, item.cvv, item.adyen_key, item.adyen_version)
    return {
        'card': cc,
        'month': mes,
        'year': ano,
        'cvv': cvv
    }
    
