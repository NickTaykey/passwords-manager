from random import choice, randint
from string import ascii_letters


class CryptographyHandler:
    _allowed_chars_tuple = (
        *tuple(ascii_letters),
        "-", "_", "#", "@",
        *(str(n) for n in range(10))
    )

    def __init__(self, secret_key=None):
        self.numeric_secret_key = CryptographyHandler._calc_numeric_secret_key(
            secret_key
        )

    @classmethod
    def _calc_numeric_secret_key(cls, secret_key):
        if secret_key:
            return sum((cls._allowed_chars_tuple.index(c) for c in secret_key))
        return secret_key

    @classmethod
    def _gen_payload(cls):
        return "".join((choice(cls._allowed_chars_tuple) for x in range(5)))

    @classmethod
    def gen_pwd(cls, service_name):
        return f"{cls._gen_payload()}{cls._rand_capitalize(service_name)}{cls._gen_payload()}"

    @classmethod
    def _rand_capitalize(cls, s):
        uppercase_chars_num = round(len(s) / 2)
        chars_list = list(s.lower())
        for x in range(3):
            idx = randint(0, uppercase_chars_num)
            chars_list[idx] = chars_list[idx].upper()
        return "".join(chars_list)

    def crypt_string(self, s):
        if self.numeric_secret_key:
            chars_list = list(s)
            allowed_chars_number = len(
                CryptographyHandler._allowed_chars_tuple
            )
            for i, l in enumerate(chars_list):
                lidx = CryptographyHandler._allowed_chars_tuple.index(l)
                nlidx = lidx + self.numeric_secret_key
                if nlidx < allowed_chars_number:
                    chars_list[i] = CryptographyHandler._allowed_chars_tuple[nlidx]
                else:
                    while nlidx >= allowed_chars_number - 1:
                        nlidx -= allowed_chars_number
                    chars_list[i] = CryptographyHandler._allowed_chars_tuple[nlidx]
            return "".join(chars_list)

    def decrypt_string(self, s):
        if self.numeric_secret_key:
            crypted_chars_list = list(s)
            allowed_chars_number = len(
                CryptographyHandler._allowed_chars_tuple
            )
            for i, l in enumerate(crypted_chars_list):
                lidx = CryptographyHandler._allowed_chars_tuple.index(l)
                olidx = lidx - self.numeric_secret_key
                while olidx < 0:
                    olidx += allowed_chars_number
                crypted_chars_list[i] = CryptographyHandler._allowed_chars_tuple[olidx]
            return "".join(crypted_chars_list)
