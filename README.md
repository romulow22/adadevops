# Jornada Digital CAIXA| Devops | #1148

## Projeto do Modulo 1: *Serviços Cloud*

- Autor: Romulo Alves | c153824

### Descrição

A Solução proposta utiliza o docker-compose para subir os serviços na ordem esperada.

Os containers foram separados por serviços (Minio, RabbitMQ e Redis) e aplicação em python (cria_amb_producer.py e cria_consumer_relatorio.py)

As rotinas dos scripts estão descritas a seguir:

1. 'cria_amb_producer.py': configura o ambiente de serviços e inicia o producer que gera requests aleatórios a partir da API do [Mockaroo](https://mockaroo.com/)
2. 'cria_consumer_relatorio.py': cria o consumidor de eventos, verifica se pode ser considerado fraudulento, gera o relatorio para os que foram considerados e disponibiliza pelo Minio para download

Os critérios para a flag de antifraude foram configuradas nesta ordem:

1. Verifica se o cookie está vencido
2. Compara sessões entre países diferentes e timestamp menor que 2 horas 
3. Verifica se o tempo de resposta é maior que 5 segundos

### Schema Utilizado para os requests

![mockaroo-schema](Modulo1/images/mockaroo-schema.png?raw=true "mockaroo-schema")

### Pré-requisitos

- docker
- docker compose
- git

## Instruções

1. Clonar o repositório

```
git clone https://github.com/romulow22/adadevops.git
```

2. Executar o ambiente 

```
sudo docker compose -f "Modulo1/docker-compose.yml" up -d --build
```  

3. Verificar os logs pelos containeres 
```
sudo docker logs --follow cria_amb_producer
sudo docker logs --follow cria_consumer_relatorio
```  

4. Remover o laboratório.  
```
sudo docker compose -f "Modulo1/docker-compose.yml" down
sudo docker rmi minio/mc:RELEASE.2024-03-07T00-31-49Z minio/minio:RELEASE.2024-03-07T00-43-48Z redis/redis-stack:7.2.0-v8 rabbitmq:3-management modulo1-baseapp modulo1-cria_amb_producer modulo1-cria_consumer_relatorio
``` 


