import os
import string
import secrets
from dataclasses import dataclass, field
from typing import Iterable, Protocol, Sequence


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


# ------------------ Políticas de Segurança ------------------

# CRIAR NOVAS POLITICAS COMO NUMERO MINIMO DE CARACTERES E SEM SEQUENCIA LOGICAS DE 3 DIGITOS

@dataclass(frozen=True) # Torna a classe imutável
class BasicPolicy:
    """Política mínima: exige minúscula, maiúscula, dígito e especial. Todas podem ser desativadas individualmente."""
    require_lower: bool = True # letra minúscula
    require_upper: bool = True # letra maiúscula
    require_digit: bool = True # dígito
    require_special: bool = True # caractere especial
    specials: str = "!@#$%&*/?" # caracteres especiais permitidos

    # Método que valida a senha de acordo com as políticas definidas -> conecta ao contrato PasswordPolicy
    def validate(self, pw: str) -> bool: # pw é a senha a ser validada
        """
        É utilizada em PasswordGenerator utilizando policies como BasicPolicy e valida em _passes_policies.
        """
        return (
            (not self.require_lower or any(c.islower() for c in pw)) and
            (not self.require_upper or any(c.isupper() for c in pw)) and
            (not self.require_digit or any(c.isdigit() for c in pw)) and
            (not self.require_special or any(c in self.specials for c in pw))
        )

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

# ------------------ Exemplo de uso ------------------

if __name__ == "__main__":
    # 1) Instância padrão com specials padrão
    gen = PasswordGenerator()

    # 2) Mudar specials via property (validação + rebuild do alfabeto)
    gen.specials = "!@#-_+"

    # 3) Gerar senha
    pwd = gen.generate(length=12, unique_chars=True)
    print("Generated password:", pwd)

    # 4) Construtor alternativo via ENV -> @classmethod
    # Se não houver ENV, gera uma senha com specials da instância padrão 
    gen_env = PasswordGenerator.from_env()
    pwd2 = gen_env.generate(length=12)
    print("ENV password:", pwd2)

    # 5) Entropia -> @staticmethod
    bits = PasswordGenerator.entropy_bits(alphabet_size=len(gen.alphabet_all), length=12)
    print(f"Entropy ~ {bits:.1f} bits")
