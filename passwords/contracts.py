from typing import Protocol, Sequence

# ------------------ Contratos/Protocolos ------------------

"""
Protocolos para garantir que as classes implementem os métodos necessários.
- PasswordPolicy: define a interface de validação de senhas -> utilizada em BasicPolicy e _passes_policies.
- RandomSource: define a interface de geração aleatória -> utilizada em SecretsRandom, _random_token e _shuffle
 e injetada no PasswordGenerator.
"""

class PasswordPolicy(Protocol):
    def validate(self, pw: str) -> bool:...

class RandomSource(Protocol):
    def choice(self, seq: Sequence[str]) -> str: ...
    def shuffle(self, x: list[str]) -> None: ...

