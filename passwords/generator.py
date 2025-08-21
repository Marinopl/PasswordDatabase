import os, string
from dataclasses import dataclass, field
from typing import Iterable
from .contracts import PasswordPolicy, RandomSource
from .rng import SecretsRandom
from .policies import BasicPolicy

# ------------------ Gerador ------------------

@dataclass
class PasswordGenerator:
    """
    Gerador configurável, com:
    - specials controlado por property (validação + recomposição de alfabeto)
    - políticas plugáveis (Strategy)
    - fonte de aleatoriedade injetável (testabilidade)
    """
    length_min: int = 10
    _specials: str = field(default="!@#$%&*/?", repr=False)  # encapsulado via property
    policies: Iterable[PasswordPolicy] = field(default_factory=lambda: [BasicPolicy()]) # coleção que passa por contrato PasswordPolicy
    rng: RandomSource = field(default_factory=SecretsRandom)

    # alfabetos salvos para uso interno (reconstruídos em __post_init__ e setter de specials)
    alphabet_letters: str = field(init=False, repr=False)
    alphabet_digits: str = field(init=False, repr=False)
    alphabet_all: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.alphabet_letters = string.ascii_letters
        self.alphabet_digits  = string.digits
        self._rebuild_alphabet()

    # ---------- Encapsulamento via property ----------
    @property # O encapsulamento permite validação e reconstrução do alfabeto
    def specials(self) -> str: # Cria um getter para ler o valor de specials -> gen = PasswordGenerator(); print(gen.specials)
        return self._specials

    @specials.setter # Um setter para modificar o valor de specials -> gen.specials = "!@#-_+", não permite espaços vazios;
    # É controlado porque o alfabeto é reconstruído.
    def specials(self, value: str) -> None:
        if not value or any(ch.isspace() for ch in value):
            raise ValueError("specials deve ser não-vazio e sem espaços.")
        self._specials = value
        self._rebuild_alphabet()

    def _rebuild_alphabet(self) -> None:
        self.alphabet_all = self.alphabet_letters + self.alphabet_digits + self._specials

    # ---------- Construtores alternativos ----------
    @classmethod
    def from_env(cls) -> "PasswordGenerator":
        """
        Construtor alternativo que lê um conjunto de variáveis diferentes das atribuidas no __init__ da classe.
        """
        specials = os.getenv("PGEN_SPECIALS", "!@#$%&*/?")
        minlen = int(os.getenv("PGEN_MINLEN", "10"))
        return cls(length_min=minlen, _specials=specials)
    
    """
    Maneiras de usar o env:
    1) Terminal do PorwerShell:
        - $env: PGEN_SPECIALS="!$%"  
        - $env: PGEN_MINLEN="14"
        - py OOP_study.py
    2) Criando arquivo .env no diretório do script:
        - PGEN_SPECIALS="!$%"
        - PGEN_MINLEN="14"
        - pip install python-dotenv
        - from dotenv import load_dotenv
        - load_dotenv()  # carrega as variáveis do .env
    """

    # ---------- Utilitário estático ----------
    @staticmethod # Não recebe nada da instância ou da classe, é apenas uma função organizada dentro da classe.
    def entropy_bits(alphabet_size: int, length: int) -> float:
        """Entropia aproximada em bits = length * log2(|alfabeto|).
        -> número de bits de entropia, que mede o espaço de busca para ataques de força bruta.
        """
        import math
        return length * math.log2(alphabet_size)

    # ---------- Núcleo de geração ----------
    # Cria a senha bruta inicial, sorteando aleatoriamente (rng) length caracteres do alfabeto completo.
    def _random_token(self, length: int) -> str:
        return ''.join(self.rng.choice(self.alphabet_all) for _ in range(length))
    
    # Valida as políticas de segurança. Garante extensibilidade para novas políticas.
    def _passes_policies(self, pw: str) -> bool:
        return all(policy.validate(pw) for policy in self.policies)

    def _deduplicate(self, pw: str) -> str:
        """
        Substitui duplicatas por caracteres ainda não usados.
        """
        alpha_set = set(self.alphabet_all)
        pw_list   = list(pw)
        first_idx = {}
        dup_idx   = []

        for i, ch in enumerate(pw_list):
            if ch in first_idx:
                dup_idx.append(i)
            else:
                first_idx[ch] = i

        used = set(pw_list)
        for i in dup_idx:
            candidates = list(alpha_set - used)
            if not candidates:
                break  # sem candidatos restantes -> nunca acontece para senhas menores que o alfabeto completo
            new_char = self.rng.choice(candidates)
            used.add(new_char)
            pw_list[i] = new_char

        return ''.join(pw_list)
    
    def _shuffle(self, pw: str) -> str:
        buf = list(pw)
        self.rng.shuffle(buf)
        return ''.join(buf)

    # ---------- API pública ----------
    def generate(
        self,
        length: int,
        unique_chars: bool = True,
        max_tries: int = 10_000,
        shuffle_final: bool = True,
    ) -> str:
        if length < self.length_min:
            raise ValueError(f"Password length should be at least {self.length_min} characters.")

        for _ in range(max_tries):
            pw = self._random_token(length)
            if not self._passes_policies(pw): # Valida as políticas de segurança
                continue

            if unique_chars:
                pw = self._deduplicate(pw)
                # garantia de que a deduplicação não quebrou política
                if not self._passes_policies(pw):
                    continue

            if shuffle_final:
                pw = self._shuffle(pw)

            return pw

        raise ValueError("Failed to generate a valid password after maximum attempts.")
