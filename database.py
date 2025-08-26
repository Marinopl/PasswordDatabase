import pandas as pd
from datetime import datetime
from passwords.generator import PasswordGenerator
from passwords.policies import BasicPolicy, MinLengthPolicy, NoSequentialPolicy

from pathlib import Path

df1 = pd.read_csv("users1.csv")
df2 = pd.read_csv("users2.csv")

gen = PasswordGenerator(policies=[BasicPolicy(), MinLengthPolicy(), NoSequentialPolicy()]) # Gerador de senha.

def ruidos(df: pd.DataFrame) -> pd.DataFrame:
    """
    Verifica se há dados faltantes no .csv.
    - Por se tratar de dados categóricos, não podemos realocar valores com médias, modas e medianas, apenas excluir.
    """

    nulls = df.isnull() # Dataframe booleano -> retorna None/NaN
    empty = df.map(lambda x: isinstance(x, str) and x.strip() == "") # Dataframe booleano -> retorna strings vazias

    mask_null = nulls.any(axis=1)
    mask_empty = empty.any(axis=1)

    n_null = int(mask_null.sum()) # Número de linhas nulas
    n_empty = int(mask_empty.sum()) # Número de linhas com strings vazis

    idx_null = df.index[mask_null].tolist() # Monta uma lista com os índices de linhas nulas
    idx_empty = df.index[mask_empty].tolist() # Monta uma lista com os índices de linhas de string vazias

    linhas_nulas = df.loc[mask_null] # Retorna um Dataframe apenas com os índices de linhas nulas
    linhas_vazias = df.loc[mask_empty] # Retorna um Dataframe apenas com os índices de linhas com strings vazias

    df = df.drop(index=idx_null)
    df = df.drop(index=idx_empty)

    df_new = df.reset_index(drop=True) # Reestrutura os índices após excluir linhas nulas e vazias.

    return df_new

def normalizar_df(data: pd.DataFrame) -> pd.DataFrame:
    df = ruidos(data)

    df["Serviço"] = df["Serviço"].str.title()
    df["Usuário"] = df["Usuário"].str.title()

    df["Senha"] = [gen.generate(10) for _ in range(len(df))]
    df["Data"] = datetime.now().strftime("%d-%m-%Y")
    df["Horário"] = datetime.now().strftime("%H:%M:%S")

    return df

def juntar_dfs(data1: pd.DataFrame, data2: pd.DataFrame) -> pd.DataFrame:
    """
    1) Pode-se utilizar a função pd.concat() -> empilha diferentes Dataframes do Pandas
    - pode ser empilhado tanto um em cima do outro quanto de lado
    - Desvantagem: não casa chaves, apenas se baseia em índices e ordem de colunas
    - UNION ALL em SQL
    """

    df_concat = pd.concat([data1, data2], ignore_index=True)

    """
    2) Pode-se utilizar a função pd.merge() -> Combina os Daframes baseados em valores de chaves
    - INNER JOIN / LEFT JOIN em SQL
    - No caso dos Dataframes aqui (df1 e df2) não possuem chaves em comum para serem linkados.
    """

    # df_merge = pd.merge(data1, data2)

    return df_concat

df1_norm = normalizar_df(ruidos(df1))
df2_norm = normalizar_df(ruidos(df2))

new_data = pd.DataFrame(juntar_dfs(df1_norm, df2_norm)).to_csv("Cadastros")


