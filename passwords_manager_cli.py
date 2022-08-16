from string import ascii_letters
from getpass import getpass
from cryptography_handler import CryptographyHandler
from passwords_storage_handler import PasswordStorageHandler


class PasswordManagerCli:
    def __init__(self):
        self.storage_handler = None

    @classmethod
    def _is_valid_string(cls, s, special_characters=()):
        return len(s) and not s.isnumeric() and all((c in ascii_letters or c.isnumeric() or c in special_characters for c in s))

    @classmethod
    def _string_input_handler(
        cls,
        data_name,
        input_description,
        input_handler=input,
        allowed_special_characters=(),
        extra_validation_func=None,
        extra_validation_func_exp_return_val=None,
        error_msg=None
    ):
        v, c = "", 0
        while not cls._is_valid_string(v, allowed_special_characters) or extra_validation_func and extra_validation_func(v) != extra_validation_func_exp_return_val:
            if c:
                print(
                    error_msg if cls._is_valid_string(v, allowed_special_characters)
                    else f'Error! Invalid {data_name} value (it contains not allowed characters)'
                )
            v = input_handler(input_description)
            c += 1
        return v

    def _multiple_passwords_generation_input_handler(self):
        services = []
        while True:
            input_message = f"Would you like to add { 'one more' if len(services) else 'a' } password to this storage (y/n): "
            if input(input_message).lower()[0] == "y":
                services.append(
                    PasswordManagerCli._string_input_handler(
                        "service name",
                        "Insert the name of the service you want to generate a password for: ",
                        allowed_special_characters=("-", "_", "."),
                    )
                )
            else:
                break
        return services

    def _storage_creation_handler(self):
        storage_name = PasswordManagerCli._string_input_handler(
            "storage name",
            "Insert the name of the storage: ",
            allowed_special_characters=("-", "_"),
            extra_validation_func=PasswordStorageHandler.check_storage_existence,
            extra_validation_func_exp_return_val=False,
            error_msg="There is already a storage with this name!",
        )
        secret_key = PasswordManagerCli._string_input_handler(
            "secret key",
            "Insert secret key you want to encrypt this storage with (do not share it to anyone):\nTYPE HERE",
            input_handler=getpass,
            allowed_special_characters=("-", "_", "@", "#")
        )
        self.storage_handler = PasswordStorageHandler(storage_name, secret_key)
        self.storage_handler.setup_storage()
        print(
            f'\nYou are successfully authenticated to the storage {storage_name}\nNow you can update it.\n'
        )
        service_names = self._multiple_passwords_generation_input_handler()
        if len(service_names):
            self.storage_handler.store_multiple_passwords(service_names)

    def _storage_authentication_hanlder(self):
        storage_name = PasswordManagerCli._string_input_handler(
            "storage name",
            "Insert the name of the storage you want to update: ",
            allowed_special_characters=("-", "_"),
            extra_validation_func=PasswordStorageHandler.check_storage_existence,
            extra_validation_func_exp_return_val=True,
            error_msg="There are no storages with this name!",
        )
        while True:
            secret_key = PasswordManagerCli._string_input_handler(
                "secret key",
                "Insert secret key of the storage:\nTYPE HERE",
                input_handler=getpass,
                allowed_special_characters=("-", "_", "@", "#")
            )
            self.storage_handler = PasswordStorageHandler(
                storage_name, secret_key
            )
            try:
                self.storage_handler.setup_storage()
            except ValueError as e:
                print(e)
            else:
                print(
                    f'\nYou are successfully authenticated to the storage {storage_name}\nNow you can update it.\n'
                )
                break

    def main_cli_controller(self):
        i = 0
        while True:
            if not i:
                print(
                    f"Password Manager Tool:\n1 - new storage\n2 - update{ ' exisiting' if not self.storage_handler else '' } storage { self.storage_handler.storage_name if self.storage_handler else '' } \n3 - storages list\n4 - generate secure password\n9 - quit"
                )
            choice = input("> ")
            if choice == "1":
                self._storage_creation_handler()
            elif choice == "2":
                if not self.storage_handler:
                    self._storage_authentication_hanlder()
                if self._update_storage_cli_controller():
                    break
                continue
            elif choice == "3":
                storages = PasswordStorageHandler.get_storages(str_output=True)
                print(storages if storages else 'There are no storages!')
            elif choice == "4":
                print(
                    f'''Your password is: {
                        CryptographyHandler().gen_pwd(
                            self._string_input_handler(
                                "service name",
                                "Insert the name of the service you want to generate a password for: ",
                                allowed_special_characters=("-", "_", ".")
                            )
                        )
                    }'''
                )
            elif choice == "9":
                print("Bye bye!")
                break
            elif not choice or choice.lower() == "menu":
                if choice:
                    print(
                        f"Password Manager Tool:\n1 - new storage\n2 - update{ ' exisiting' if not self.storage_handler else '' } storage { self.storage_handler.storage_name if self.storage_handler else '' } \n3 - storages list\n4 - generate secure password\n9 - quit"
                    )
                i += 1
                continue
            else:
                print("Unknown command, type: 'menu' to checkout what you can do...")
                i += 1

    def _update_storage_cli_controller(self):
        i = 0
        while True:
            menu_options = f"Update storage {self.storage_handler.storage_name}:\n1 - generate and store a secure password for a service\n2 - generate and store secure passwords for multiple services\n3 - change the password for a service\n4 - delete a password from the storage\n5 - decrypt the storage to a csv file\n0 - back\n9 - quit"
            if not i:
                print(menu_options)
            choice = input("> ")
            if choice == "1":
                service_name = self._string_input_handler(
                    "service name",
                    "Insert the name of the service you want to generate a password for: ",
                    allowed_special_characters=("-", "_", "."),
                )
                self.storage_handler.store_single_password(service_name)
            elif choice == "2":
                service_names = self._multiple_passwords_generation_input_handler()
                self.storage_handler.store_multiple_passwords(service_names)
            elif choice == "3":
                service_name = self._string_input_handler(
                    "service name",
                    "Insert the name of the service you want to change the password: ",
                    allowed_special_characters=("-", "_", ".")
                )
                self.storage_handler.regenerate_service_password(
                    service_name, direct_usage=True
                )
            elif choice == "4":
                service_name = self._string_input_handler(
                    "service name",
                    "Insert the name of the service you want delete from the storage: ",
                    allowed_special_characters=("-", "_", ".")
                )
                self.storage_handler.delete_password_from_storage(
                    service_name, direct_usage=True
                )
            elif choice == "5":
                self.storage_handler.decrypt_storage()
            elif not choice or choice.lower() == "menu":
                if choice:
                    print(menu_options)
                i += 1
                continue
            elif choice == "0":
                return False
            elif choice == "9":
                print("Bye bye!")
                break
            else:
                print("Unknown command, type: 'menu' to checkout what you can do...")
                i += 1
        return True


PasswordManagerCli().main_cli_controller()
