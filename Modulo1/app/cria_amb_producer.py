import json
import pika
import minio
import redis
import requests
import random
import time

# Configuração do RabbitMQ
def setup_rabbitmq():

    exchange_name = 'transaction_exchange'
    transaction_queue_name = 'transaction_queue'
    antifraud_queue_name = 'antifraud_queue'
    routing_key = 'transaction_routing_key'
    
    credentials = pika.PlainCredentials('admin', 'admin1234')
    connection_params = pika.ConnectionParameters(host='rabbitmq', port=5672, virtual_host='projetoada', credentials=credentials)
    connection = pika.BlockingConnection(connection_params)
    channel = connection.channel()
    
    # Verifica se a exchange existe
    try:
        channel.exchange_declare(exchange=exchange_name, exchange_type='direct', passive=True)
        print(f"Exchange '{exchange_name}' já existe.")
    except pika.exceptions.ChannelClosedByBroker:
        # Se não existir, reabrimos o canal e declaramos a exchange
        channel = channel.connection.channel()
        channel.exchange_declare(exchange=exchange_name, exchange_type='direct')
        print(f"Exchange '{exchange_name}' criado.")
    
    # Verifica se a fila transaction_queue_name existe
    try:
        channel.queue_declare(queue=transaction_queue_name, passive=True)
        print(f"Queue '{transaction_queue_name}' já existe.")
    except pika.exceptions.ChannelClosedByBroker:
        # Se não existir, reabrimos o canal e declaramos a fila
        channel = channel.connection.channel()
        channel.queue_declare(queue=transaction_queue_name)
        print(f"Queue '{transaction_queue_name}' criado.")

    # Verifica se a fila antifraud_queue_name existe
    try:
        channel.queue_declare(queue=antifraud_queue_name, passive=True)
        print(f"Queue '{antifraud_queue_name}' já existe.")
    except pika.exceptions.ChannelClosedByBroker:
        # Se não existir, reabrimos o canal e declaramos a fila
        channel = channel.connection.channel()
        channel.queue_declare(queue=antifraud_queue_name)
        print(f"Queue '{antifraud_queue_name}' criado.")
    
    channel.queue_bind(queue=transaction_queue_name, exchange=exchange_name, routing_key=routing_key)
    channel.queue_bind(queue=antifraud_queue_name, exchange=exchange_name, routing_key=routing_key)
        
    print("RabbitMQ configurado com sucesso!")
    return connection, channel

# Configuração do MinIO
def setup_minio():    
    bucket_name = "reportes-antifraude"
    bucket_policy = {
    "Version": "2012-10-17",
    "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": ["*"]},
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket_name}/*"]
            }
        ]
    }
    policy_json = json.dumps(bucket_policy)  
       
    client = minio.Minio("minio:9000", access_key="admin", secret_key="admin1234", secure=False)
    found = client.bucket_exists(bucket_name)
    if not found:
        client.make_bucket(bucket_name)
        print("Bucket criado com sucesso!")
    else:
        print(f"Bucket {bucket_name} já existe!")
    client.set_bucket_policy(bucket_name, policy_json)
    print("Minio configurado com sucesso!")
    


# Produção de mensagens
def publish_message(channel, exchange_name, routing_key, message):
    properties = pika.BasicProperties( content_type='application/json', expiration='10000')
    channel.basic_publish(exchange=exchange_name, routing_key=routing_key, body=message, properties=properties)
    print(" [x] Message Sent ")
    
    
def publish_json_to_exchange(channel, exchange_name, routing_key, count):
    url = f"https://api.mockaroo.com/api/0eee3010?count={count}&key=31e736b0"
    response = requests.get(url)
    print(f"Status code: {response.status_code}")
    print(f"Response: {response.text}")
    if response.status_code == 200 and "error" not in response.text:
        json_objects = response.json()
    else:
        url = f"https://api.mockaroo.com/api/6ffc21b0?count={count}&key=e3a906f0"
        response = requests.get(url)
        response.raise_for_status()  # Levanta uma exceção para respostas 4xx/5xx
        json_objects = response.json()
    messages_sent = 0
    for obj in json_objects:        
        message = json.dumps(obj)
        properties = pika.BasicProperties(content_type='application/json')
        channel.basic_publish(exchange=exchange_name, routing_key=routing_key, body=message, properties=properties)
        messages_sent += 1
    print(f" [x] {messages_sent} Mensagem(s) Enviada(s)")  

def main():
    #RabbitMQ
    connection, channel = setup_rabbitmq()
    # MinIO
    setup_minio()
    #Producer
    try:
        exchange_name = 'transaction_exchange'
        routing_key = 'transaction_routing_key'
        while True:
            count = random.randint(10, 20)  # Gera um número aleatório entre 1 e 10
            publish_json_to_exchange(channel, exchange_name, routing_key, count)
            time.sleep(60)  # Aguarda 3 segundos antes de publicar novamente
    except KeyboardInterrupt:
        print("Script interrompido pelo usuário")
    finally:
        channel.close()
        connection.close()    

if __name__ == "__main__":
    main()
