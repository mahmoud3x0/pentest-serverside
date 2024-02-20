#Auther: mahmoud3x0

# URL Encoding & Decoding
# HTML Encoding & Decoding
# Base32 Encoding & Decoding
# Base64 Encoding & Decoding
# ROT13 Encoding & Decoding
# Binary Encoding & Decoding
# Hexa Encoding & Decoding
# Octal Encoding & Decoding

import urllib.parse
import html
import base64
# import base58
import codecs
import binascii

def url_encode(decoded_value):
    return urllib.parse.quote(decoded_value)

def url_decode(encoded_value):
    return urllib.parse.unquote(encoded_value)

def html_encode(decoded_value):
    return html.escape(decoded_value)

def html_decode(encoded_value):
    return html.unescape(encoded_value)

def base32_encode(decoded_value):
    return base64.b32encode(decoded_value.encode()).decode()

def base32_decode(encoded_value):
    return base64.b32decode(encoded_value).decode()

# def base58_encode(decoded_value):
#     return base58.b58encode(decoded_value.encode()).decode()
#
# def base58_decode(encoded_value):
#     return base58.b58decode(encoded_value).decode()

def base64_encode(decoded_value):
    return base64.b64encode(decoded_value.encode()).decode()

def base64_decode(encoded_value):
    return base64.b64decode(encoded_value).decode()

def rot13_encode(decoded_value):
    return codecs.encode(decoded_value, 'rot_13')

def rot13_decode(encoded_value):
    return codecs.encode(encoded_value, 'rot_13')

def binary_encode(decoded_value):
    return ''.join(format(ord(char), '08b') for char in decoded_value)

def binary_decode(encoded_value):
    try:
        binary_values = [encoded_value[i:i+8] for i in range(0, len(encoded_value), 8)]
        return ''.join(chr(int(b, 2)) for b in binary_values)
    except:
        decimal_result = ""
        current_binary = ""

        for char in encoded_value:
            if char in ('0', '1'):
                current_binary += char
            else:
                if current_binary:
                    decimal_result += str(int(current_binary, 2))
                    current_binary = ""
                decimal_result += char

        if current_binary:
            decimal_result += str(int(current_binary, 2))

        return decimal_result

def hex_encode(decoded_value):
    return binascii.hexlify(decoded_value.encode()).decode()

def hex_decode(encoded_value):
    try:
        return binascii.unhexlify(encoded_value).decode()
    except:
        decimal_result = ""
        current_hex = ""

        for char in encoded_value:
            if char.isdigit() or (char.lower() in ('a', 'b', 'c', 'd', 'e', 'f')):
                current_hex += char
            else:
                if current_hex:
                    decimal_result += str(int(current_hex, 16))
                    current_hex = ""
                decimal_result += char

        if current_hex:
            decimal_result += str(int(current_hex, 16))

        return decimal_result

def octal_encode(decoded_value):
    return ''.join(format(ord(char), 'o') for char in decoded_value)

def octal_decode(encoded_value):
    try:
        octal_values = encoded_value.split()
        return ''.join(chr(int(octal, 8)) for octal in octal_values)
    except:
        decimal_result = ""
        current_octal = ""

        for char in encoded_value:
            if char in ('0', '1', '2', '3', '4', '5', '6', '7'):
                current_octal += char
            else:
                if current_octal:
                    decimal_result += str(int(current_octal, 8))
                    current_octal = ""
                decimal_result += char

        if current_octal:
            decimal_result += str(int(current_octal, 8))

        return decimal_result

def main(input_string, type, op):
    # URL encode & decode
    if type.lower() == "url":
        if op.lower() == "encode":
            url_encoded = url_encode(input_string)
            print(f"URL Encoded: {url_encoded}")
        elif op.lower() == "decode":
            try:
                url_decoded = url_decode(input_string)
                print(f"URL Decoded: {url_decoded}\n")
            except Exception as error:
                print(f"invalid input\n", error)


    elif type.lower() == "html":
        # HTML encode & decode
        if op.lower() == "encode":
            html_encoded = html_encode(input_string)
            print(f"HTML Encoded: {html_encoded}")
        elif op.lower() == "decode":
            try:
                html_decoded = html_decode(input_string)
                print(f"HTML Decoded: {html_decoded}\n")
            except Exception as error:
                print(f"invalid input\n", error)

    # Base32 encode & decode
    elif type.lower() == "base32":
        if op.lower() == "encode":
            base32_encoded = base32_encode(input_string)
            print(f"Base32 Encoded: {base32_encoded}")
        elif op.lower() == "decode":
            try:
                base32_decoded = base32_decode(input_string)
                print(f"Base32 Decoded: {base32_decoded}\n")
            except Exception as error:
                print(f"invalid input\n", error)

    # Base58 encode & decode
    # elif type.lower() == "base58":
    #     if op.lower() == "encode":
    #         base58_encoded = base58_encode(input_string)
    #         print(f"Base58 Encoded: {base58_encoded}")
    #     elif op.lower() == "decode":
    #         try:
    #             base58_decoded = base58_decode(input_string)
    #             print(f"Base58 Decoded: {base58_decoded}\n")
    #         except Exception as error:
    #             print(f"invalid input!\n")
    #             self.show_error_message(e)


    # Base64 encode & decode
    elif type.lower() == "base64":
        if op.lower() == "encode":
            base64_encoded = base64_encode(input_string)
            print(f"Base64 Encoded: {base64_encoded}")
        elif op.lower() == "decode":
            try:
                base64_decoded = base64_decode(input_string)
                print(f"Base64 Decoded: {base64_decoded}\n")
            except Exception as error:
                print(f"invalid input\n", error)

    # ROT13 encode & decode
    elif type.lower() == "rot13":
        if op.lower() == "encode":
            rot13_encoded = rot13_encode(input_string)
            print(f"ROT13 Encoded: {rot13_encoded}")
        elif op.lower() == "decode":
            try:
                rot13_decoded = rot13_decode(input_string)
                print(f"ROT13 Decoded: {rot13_decoded}\n")
            except Exception as error:
                print(f"invalid input\n", error)

    # Binary encode & decode
    elif type.lower() == "binary":

        if op.lower() == "encode":
            binary_encoded = binary_encode(input_string)
            print(f"Binary Encoded: {binary_encoded}")
        elif op.lower() == "decode":
            try:
                binary_decoded = binary_decode(input_string)
                print(f"Binary Decoded: {binary_decoded}\n")
            except Exception as error:
                print(f"invalid input\n", error)

    # Hexa encode & decode
    if type.lower() == "hexa":
        if op.lower() == "encode":
            hex_encoded = hex_encode(input_string)
            print(f"Hex Encoded: {hex_encoded}")
        elif op.lower() == "decode":
            try:
                hex_decoded = hex_decode(input_string)
                print(f"Hex Decoded: {hex_decoded}\n")
            except Exception as error:
                print(f"invalid input\n", error)
    # Octal encode & decode
    if type.lower() == "octal":
        if op.lower() == "encode":
            octal_encoded = octal_encode(input_string)
            print(f"Octal Encoded: {octal_encoded}")
        elif op.lower() == "decode":
            try:
                octal_decoded = octal_decode(input_string)
                print(f"Octal Decoded: {octal_decoded}\n")
            except Exception as error:
                print(f"invalid input\n", error)


if __name__ == "__main__":
    input_string = str(input("Enter the string: "))
    type = str(input("URL, HTML, Base32, Base64, ROT13, Binary, Hexa, Octal? "))
    op = str(input("encode or decode? "))
    main(input_string, type, op)
