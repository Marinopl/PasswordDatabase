# PasswordDatabase - Estudos de Programação Orientada a Objetos e Pandas

Este repositório foi desenvolvido exclusivamente para estudos de lógica de programação, testando o uso de classes (POO) e Dataframes em Python. O Projeto explora conceitos classes estáticas, protocolos, encapsulamento com @Property e extensibilidade.

> Projeto feito no estilo Vibe Coding utilizando o CHatGPT 5 como ferramenta de aprendizado interativo.

## Objetivo do Projeto
- Praticar conceitos de POO em Python de forma lógica, entendendo as aplicações de classes e objetos;
- Criar um gerador de senhas seguro, modular e extensível;
- Testar contratos com Protocol, dataclasses, encapsulamento via @Property e métodos estatícos;
- Atribuir Dataframes fictícios para explorar a conexão com o gerador de senhas.

---

## Funcionalidades
- Geração de senhas seguras com:
    - letras maiúsculas e minúsculas;
    - dígitos numéricos
    - caracteres especiais
- Políticas customizáveis.
- Controle de duplicação de caracters.
- Extensibilidade para novas políticas.
- Calculo de entropia em bits para garantir a complexidade da senha.

---

## Estrutura do Projeto
```
PasswordDatabase/
│
├── passwords/
│ ├── contracts.py # Protocolos das validações necessárias
│ ├── generator.py # Núcleo de geração de senhas
│ ├── policies.py # Políticas de senha (extensível)
│ ├── rng.py # Fonte de aleatoriedade criptográfica
│
├── main.py # Exemplos de uso e aplicabilidade
├── OOP_study.py # Base dos estudos antes de modularizar
├── original_code.py # Código original sem POO e sem Vibe Coding (ponto de partida)
├── database.py # Utilização da biblioteca Pandas para implementação de senhas em banco de dados fictíticos.
```

* contracts.py: protocola as validações necessárias.
* policies.py: garante as políticas de senha a ser gerada (passível a extensão)
* rng.py: garante a escolhas aleatórias e criptografadas para a formação da senha
* generator.py: gera senhas criptografadas que obedecem aos contratos e políticas estabelecidas.
* main.py: exemplos de uso e aplicabilidade
* OOP_study: base dos estudos de POO antes de modularizar
* original_code.py: código original realizado sem o uso de IA para entender lógica de programação por trás de criptografias.

---

## Próximos Passos
- Estudar como este gerador de senhas pode ser implementado em um Dataframe do Pandas, utilizando usuários fictícios.

> **Importante:** Este projeto é apenas para estudo. Não foi testado nem validade para uso em sistemas de segurança.

---

## Bibliotecas utilizadas
- Python 3.11+
- secrets -> geração de token aleatórios criptograficamente seguros
- sataclasses -> criação de classes imutáveis
- typing.Protocol -> definição de contratos e validação

---

## Como Executar
python -m PasswordDatabase.main
