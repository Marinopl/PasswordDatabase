from dataclasses import dataclass
from .contracts import PasswordPolicy
import string

# ------------------ Políticas de Segurança ------------------

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
    
@dataclass(frozen=True)
class MinLengthPolicy:
    """ Política de tamanho mínimo para a senha. """
    min_len: int = 10
    def validate(self, pw: str) -> bool:
        return len(pw) >= self.min_len
    
@dataclass(frozen=True)
class NoSequentialPolicy:
    """ Política de não sequenciamento de 3 digitos ou letras."""
    run_len: int = 3
    def validate(self, pw: str) -> bool:
        numb = string.digits
        alph = string.ascii_letters
        
        forbidden = []

        for i in range(len(numb) - self.run_len + 1):
            forbidden.append(numb[i:i+self.run_len]) # Percorre trincas da string

        for i in range(len(alph) - self.run_len + 1): 
            forbidden.append(alph[i:i+self.run_len]) # Percorre trincas da string

        for seq in forbidden:
            if seq in pw:
                return False
        
        return True