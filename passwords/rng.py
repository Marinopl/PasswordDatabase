import secrets
from typing import Sequence
from .contracts import RandomSource

# ------------------ Implementações utilitárias ------------------

"""
Implementação do contrato de aleatoriedade definido em RandomSource.
1) A senha inicial é gerada com _random_token() dentro de PasswordGenerator, atribuindo RandomSource com SecretsRandom a
partir do alfabeto completo em _rebuild_alphabet().
2) Em seguida, o método _shuffle() utiliza o método shuffle() do SecretsRandom para embaralhar a senha.
"""

class SecretsRandom:
    def __init__(self) -> None:
        self._rng = secrets.SystemRandom()
    def choice(self, seq: Sequence[str]) -> str:
        return self._rng.choice(seq)
    def shuffle(self, x: list[str]) -> None:
        self._rng.shuffle(x)
