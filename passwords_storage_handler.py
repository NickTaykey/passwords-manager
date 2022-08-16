from cryptography_handler import CryptographyHandler
from json import load, dump
from hashlib import sha512
from os import listdir
from csv import reader, writer


class PasswordStorageHandler:
    _data_directory_path = '/Users/toccanen/Desktop/programming/python/exercises/passwords_manager/data'
    _storages_index_json_file_path = f"{_data_directory_path}/storages_index.json"
    _storage_csv_file_headers = ("Service name", "Password")

    def __init__(self, storage_name, secret_key):
        self.storage_name = storage_name
        self.secret_key = secret_key
        self.current_storage, self.crypto_handler = None, None
        self._storage_csv_file_path = f"{PasswordStorageHandler._data_directory_path}/storages/{storage_name}.csv"

    @classmethod
    def get_storages(cls, str_output=False):
        with open(cls._storages_index_json_file_path) as f:
            storages_index = load(f)["storages_index"]
        if str_output:
            storage_names = [s["name"] for s in storages_index]
            if len(storage_names) > 1:
                return ", ".join(storage_names[0:-1]) + " and " + storage_names[-1]
            elif len(storage_names):
                return storage_names[0]
            return None
        return storages_index

    @classmethod
    def _get_storage(cls, storage_name):
        for s in cls.get_storages():
            if s["name"] == storage_name:
                return s

    @classmethod
    def check_storage_existence(cls, storage_name):
        return bool(cls._get_storage(storage_name))

    @classmethod
    def _authenticate_storage_owner(cls, storage_name, secret_key):
        return sha512(secret_key.encode()).hexdigest() == cls._get_storage(storage_name)["secret_key"]

    def get_stored_passwords_num(self):
        with open(f"{PasswordStorageHandler._data_directory_path}/storages/{self.storage_name}.csv") as f:
            return len(tuple(reader(f))) - 1

    def check_if_password_stored_by_service_name(self, service_name):
        service_name = service_name.lower()
        with open(f"{PasswordStorageHandler._data_directory_path}/storages/{self.storage_name}.csv") as f:
            for r in tuple(reader(f))[1:]:
                if self.crypto_handler.decrypt_string(r[0]).lower() == service_name:
                    return True
            return False

    def _create_storage(self):
        storages_index = PasswordStorageHandler.get_storages()
        storages_index.append(self.current_storage)
        try:
            with open(PasswordStorageHandler._storages_index_json_file_path, "w") as f:
                dump({"storages_index": storages_index}, f)
        except Exception:
            print("Unexpected exception! Storage not created, try again later.")
        else:
            print("\nStorage successfully created!")

    def setup_storage(self):
        if PasswordStorageHandler.check_storage_existence(self.storage_name):
            if PasswordStorageHandler._authenticate_storage_owner(self.storage_name, self.secret_key):
                self.current_storage = PasswordStorageHandler._get_storage(
                    self.storage_name
                )
                self.crypto_handler = CryptographyHandler(self.secret_key)
                return self.current_storage
            raise ValueError("Incorrect secret key")
        else:
            self.current_storage = {
                "name": self.storage_name,
                "secret_key": sha512(self.secret_key.encode()).hexdigest()
            }
            self.crypto_handler = CryptographyHandler(self.secret_key)
            self._create_storage()

    def _create_not_existing_storage_csv_file(self):
        if f"{self.storage_name}.csv" not in listdir(f"{self._data_directory_path}/storages"):
            open(
                f"{self._data_directory_path}/storages/{self.storage_name}.csv", "w"
            ).close()

    def store_single_password(self, service_name):
        self._create_not_existing_storage_csv_file()
        if not self.check_if_password_stored_by_service_name(service_name):
            with open(self._storage_csv_file_path) as f:
                csv_reader = reader(f)
                rows_to_write = (
                    self._storage_csv_file_headers,
                    *(r for i, r in enumerate(csv_reader) if i),
                    (
                        self.crypto_handler.crypt_string(service_name),
                        self.crypto_handler.crypt_string(
                            self.crypto_handler.gen_pwd(service_name)
                        )
                    )
                )
            with open(self._storage_csv_file_path, "w") as f:
                writer(f).writerows(rows_to_write)
            print(f"Password for {service_name} successfully added!")
        else:
            input_message = f"There is already a password stored for service: '{service_name}' in storage: '{self.storage_name}' ...\nWould you like to override it with a newly generated password (y/n): "
            if input(input_message).lower()[0] == "y":
                self.regenerate_service_password(
                    service_name
                )
                print(f"Password for {service_name} successfully updated!")
            else:
                print("Operation aborted!")

    def store_multiple_passwords(self, service_names):
        self._create_not_existing_storage_csv_file()
        new_service_names = []
        for n in service_names:
            if self.check_if_password_stored_by_service_name(n):
                if input(f"There is already a password stored for service: '{n}' in storage: '{self.storage_name}' ...\nWould you like to override it with a newly generated password (y/n): ").lower()[0] == "y":
                    self.regenerate_service_password(n)
            else:
                new_service_names.append(n)
        with open(f"{PasswordStorageHandler._data_directory_path}/storages/{self.storage_name}.csv", "r") as f:
            rows = (
                PasswordStorageHandler._storage_csv_file_headers,
                *(
                    *(r for i, r in enumerate(reader(f)) if i),
                    *zip(
                        [
                            self.crypto_handler.crypt_string(s)
                            for s in new_service_names
                        ],
                        [
                            self.crypto_handler.crypt_string(
                                self.crypto_handler.gen_pwd(s)
                            )
                            for s in new_service_names
                        ]
                    )
                )
            )
        with open(self._storage_csv_file_path, "w") as f:
            writer(f).writerows(rows)
        print(f"\nPasswords successfully saved in the storage!\n")

    def delete_password_from_storage(self, service_name, internal_use=False, direct_usage=False):
        with open(self._storage_csv_file_path) as f:
            service_name = service_name.lower()
            decrypted_rows = [
                (
                    self.crypto_handler.decrypt_string(r[0]),
                    self.crypto_handler.decrypt_string(r[1])
                )
                for i, r in enumerate(reader(f)) if i
            ]
            updated_rows = [
                r for r in decrypted_rows if r[0].lower() != service_name
            ]
            if len(decrypted_rows) == len(updated_rows):
                print(
                    f"Error! No passwords found for {service_name} in storage: {self.storage_name}"
                )
            else:
                with open(self._storage_csv_file_path, "w") as f:
                    writer(f).writerows(
                        (
                            PasswordStorageHandler._storage_csv_file_headers,
                            *[
                                (
                                    self.crypto_handler.crypt_string(r[0]),
                                    self.crypto_handler.crypt_string(r[1])
                                )
                                for r in updated_rows
                            ]
                        )
                    )
                if direct_usage:
                    print("\nPassword successfully deleted!\n")
                if internal_use:
                    return next((r for r in decrypted_rows if r[0].lower() == service_name))

    def regenerate_service_password(self, service_name, direct_usage=False):
        prev_len = self.get_stored_passwords_num()
        deleted_service_name = self.delete_password_from_storage(
            service_name, internal_use=True
        )[0]
        last_len = self.get_stored_passwords_num()
        if prev_len > last_len:
            with open(self._storage_csv_file_path, "a") as f:
                writer(f).writerow(
                    (
                        self.crypto_handler.crypt_string(deleted_service_name),
                        self.crypto_handler.crypt_string(
                            self.crypto_handler.gen_pwd(service_name)
                        )
                    )
                )
        if direct_usage:
            print("\nPassword successfully re-generated!\n")

    def decrypt_storage(self):
        try:
            with open(self._storage_csv_file_path) as f:
                with open(f"{PasswordStorageHandler._data_directory_path}/decrypted_storages/{self.storage_name}.csv", "w") as of:
                    decrypted_rows = [
                        (
                            self.crypto_handler.decrypt_string(r[0]),
                            self.crypto_handler.decrypt_string(r[1])
                        )
                        if i else r for i, r in enumerate(reader(f))
                    ]
                    writer(of).writerows(decrypted_rows)
        except Exception as e:
            print(
                f"\nUnexpected error, the storage: '{self.storage_name}' cannot be decrypted at the moment, try again later ...\n{e}\n"
            )
        else:
            print(
                f"\nStorage: '{self.storage_name}' successfully decrypted!\nYou can find your passwords in this file: '{PasswordStorageHandler._data_directory_path}/decrypted_storages/{self.storage_name}.csv'\n"
            )
