# Use a imagem base do Python 3.9
FROM python:3.9

# Define o diretório de trabalho dentro do contêiner
WORKDIR /app

# Copia o arquivo requirements.txt para o diretório de trabalho
COPY requirements.txt .

# Instala as dependências do projeto
RUN pip install --no-cache-dir -r requirements.txt

# Variavel default
ENV PYTHONUNBUFFERED 1

# Instalando pacotes customizados
RUN apt-get update && apt-get install -y netcat-openbsd curl wget && rm -rf /var/lib/apt/lists/*

# Define o comando padrão para executar a aplicação
#CMD ["python", "app.py"]

#inicia o servidor flask em modo de desenvolvimento 
#CMD ["flask", "run", "--host=0.0.0.0", "--port=5000", "--reload"]

# Expõe a porta 5000 para acesso à API
EXPOSE 5000

