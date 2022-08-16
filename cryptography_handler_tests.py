from cryptography_handler import CryptographyHandler
import unittest


class TestCryptoPasswordManager(unittest.TestCase):
    def setUp(self):
        self.manager = CryptographyHandler("secret")
        self.service_name = "linkedin"
        self.pwd = self.manager.gen_pwd(self.service_name)
        self.crypted_pwd = self.manager.crypt_string(
            self.pwd
        )

    def test_rand_capitalize(self):
        self.assertNotEqual(
            self.service_name, self.manager._rand_capitalize(self.service_name)
        )
        self.assertEqual(
            self.service_name,
            self.manager._rand_capitalize(
                self.service_name
            ).lower()
        )

    def test_gen_pwd(self):
        self.assertIsInstance(self.pwd, str)
        self.assertEqual(len(self.pwd), 10 + len(self.service_name))

    def test_crypt_password(self):
        self.assertEqual(len(self.crypted_pwd), len(self.pwd))

    def test_decrypt_password(self):
        self.assertEqual(
            self.manager.decrypt_string(self.crypted_pwd),
            self.pwd
        )


if __name__ == "__main__":
    unittest.main()
