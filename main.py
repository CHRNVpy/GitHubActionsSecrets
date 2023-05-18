import requests
from base64 import b64encode
from nacl import encoding, public


class GitHubSecret:
    """
        A class for interacting with GitHub repository secrets.

        This class provides methods to manage secrets in a GitHub repository, including creating, updating, and deleting
        secrets. It uses the GitHub Actions API to perform these operations.

        Attributes:
            owner_name (str): The name of the repository owner.
            repo_name (str): The name of the repository.
            token (str): Personal access token with the necessary permissions to access and manage repository secrets.
            session (requests.Session): Session object for making HTTP requests to the GitHub API.
            headers (dict): HTTP headers used in API requests.

        Methods:
            __init__(owner_name: str, repo_name: str, token: str):
                Initializes a GitHubSecret instance with the owner name, repository name, and access token.

            _get_public_key():
                Retrieves the public key used for encrypting secrets in the repository.

            get_secret():
                Retrieves all secrets in the repository.

            create_update_secret(secret_name: str, value: str):
                Creates or updates a secret in the repository with the specified name and value.

            delete_secret(secret_name: str):
                Deletes a secret from the repository.

        Usage:
            # Initialize GitHubSecret with owner name, repository name, and personal access token
            secret = GitHubSecret('owner_name', 'repo_name', 'personal_access_token')

            # Get all secrets in the repository
            secret._get_secret()

            # Create or update a secret
            secret.create_update_secret('secret_name', 'secret_value')

            # Delete a secret
            secret.delete_secret('secret_name')
        """

    def __init__(self, repo_url: str, token: str):
        """
        Initializes a GitHubSecret instance with the specified owner name, repository name, and access token.

        Args:
            owner_name (str): The name of the repository owner.
            repo_name (str): The name of the repository.
            token (str): Personal access token with the necessary permissions to access and manage repository secrets.
        """
        self.owner_name = repo_url.split('/')[3]
        self.repo_name = repo_url.split('/')[4]
        self.token = token
        self.session = requests.Session()
        self.headers = {
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {token}',
            'X-GitHub-Api-Version': '2022-11-28',
        }
        self.session.headers.update(self.headers)

    def _get_public_key(self):
        """
        Retrieves the public key used for encrypting secrets in the repository.

        Returns:
            dict: JSON response containing the public key and key ID.
        """
        response = self.session.get(f'https://api.github.com/repos/{self.owner_name}/{self.repo_name}/actions/secrets/'
                                    f'public-key')
        return response.json()

    def list_secrets(self):
        """
           Retrieves all secrets in the repository.

           Prints:
               JSON response containing the secrets in the repository.
        """
        response = self.session.get(f'https://api.github.com/repos/{self.owner_name}/{self.repo_name}/actions/secrets')
        print(response.json())

    def get_secret(self, secret_name):
        """
           Retrieves exact secret from the repository.

           Prints:
               JSON response containing the secret in the repository.
        """
        response = self.session.get(f'https://api.github.com/repos/{self.owner_name}/{self.repo_name}/actions/secrets/'
                                    f'{secret_name}')
        print(response.json())

    def create_update_secret(self, secret_name: str, value: str):
        """
        Creates or updates a secret in the repository with the specified name and value.

        Args:
            secret_name (str): The name of the secret.
            value (str): The value of the secret.

        Prints:
            Success message if the secret is created or updated.
            Error message if the operation fails.
        """
        headers = {
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {self.token}',
            'X-GitHub-Api-Version': '2022-11-28',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        def encrypt(public_key: str, secret_value: str) -> str:
            """Encrypts a Unicode string using the public key."""
            public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
            sealed_box = public.SealedBox(public_key)
            encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
            return b64encode(encrypted).decode("utf-8")

        pub_key = self._get_public_key()
        data = encrypt(pub_key['key'], value)
        creds = {"encrypted_value": data,
                 "key_id": pub_key['key_id']}
        self.session.headers.update(headers)
        response = self.session.put(f'https://api.github.com/repos/{self.owner_name}/{self.repo_name}/actions/secrets/'
                                    f'{secret_name}', json=creds)
        # return response.json()
        if response.status_code == 201:
            print('secret created')
            # return response.json()
        elif response.status_code == 204:
            print('secret updated')
            # return response.json()
        else:
            print(response.status_code, 'error')

    def delete_secret(self, secret_name: str):
        """
            Deletes a secret from the repository.

            Args:
                secret_name (str): The name of the secret.

            Prints:
                Success message if the secret is deleted.
                Error message if the operation fails.
        """
        response = self.session.delete(f'https://api.github.com/repos/CHRNVpy/test/actions/secrets/{secret_name}')
        if response.status_code == 201:
            print(f'Secret "{secret_name}" successfully created.')
        else:
            print(f'Failed to create secret "{secret_name}".')
            print(f'Response: {response.text}')
