# Exemplo de uso

from passwords.generator import PasswordGenerator
from passwords.policies import BasicPolicy, MinLengthPolicy, NoSequentialPolicy

if __name__ == "__main__":
    gen = PasswordGenerator(
        policies=[BasicPolicy(), MinLengthPolicy(14), NoSequentialPolicy(3)]
    )
    print("Generated:", gen.generate(length=16, unique_chars=True))

    gen_env = PasswordGenerator.from_env()
    print("ENV:", gen_env.generate(length=12))

    bits = PasswordGenerator.entropy_bits(len(gen.alphabet_all), 12)
    print(f"Entropy ~ {bits:.1f} bits")