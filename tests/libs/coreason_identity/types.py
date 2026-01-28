from pydantic import SecretStr as PydanticSecretStr


class SecretStr(PydanticSecretStr):
    pass
