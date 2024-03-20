import pika
import redis
import minio
import io
from datetime import datetime, timedelta, timezone
import json

def connect_rabbitmq():
    credentials = pika.PlainCredentials('admin', 'admin1234')
    connection_params = pika.ConnectionParameters(host='rabbitmq', port=5672, virtual_host='projetoada', credentials=credentials)
    connection = pika.BlockingConnection(connection_params)
    return connection

# Configuração do Redis
def connect_redis():
    cache = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)
    return cache

# Definição da regra de fraude
def is_fraudulent(event, redis_client):
    session_id = event['session_id']
    country = event['country']
    fraud_reasons = []

    # Parse the event timestamp as an offset-aware datetime object
    timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
    
    # Parse the cookie_expiration field
    if ' UTC' in event['cookie_expiration']:
        cookie_expiration_str = event['cookie_expiration'].replace(' UTC', '')
        # Assuming the cookie expiration date is in UTC, we add the timezone information
        cookie_expiration = datetime.fromisoformat(cookie_expiration_str).replace(tzinfo=timezone.utc)
    else:
        # If it's already in an ISO format, just replace 'Z' with timezone information
        cookie_expiration = datetime.fromisoformat(event['cookie_expiration'].replace('Z', '+00:00'))
    
    # Now both cookie_expiration and timestamp are offset-aware and can be compared
    if cookie_expiration < timestamp:
        fraud_reasons.append('Cookie Expirado')

    # Verifica a diferença de tempo entre sessões em países diferentes
    last_event_json = redis_client.get(session_id)
    if last_event_json:
        last_event = json.loads(last_event_json)
        last_country = last_event['country']
        last_timestamp = datetime.fromisoformat(last_event['timestamp'].replace('Z', '+00:00'))
        if last_country != country:
            time_difference = timestamp - last_timestamp
            if time_difference < timedelta(hours=2) and time_difference.total_seconds() > 0:
                fraud_reasons.append('Diferença entre paises menor que 2 horas.')
            elif time_difference.total_seconds() < 0:  # Event came out of order
                return False, fraud_reasons  # Do not flag as fraud but also do not update Redis

    # Verifica se o tempo de resposta é muito alto
    response_time_threshold = 5000
    if event.get('response_time', 0) > response_time_threshold:
        fraud_reasons.append('Response Time maior que 5 segundos.')

    # Atualiza o evento no Redis apenas se for mais recente que o último evento armazenado
    if not last_event_json or timestamp >= last_timestamp:
        redis_client.set(session_id, json.dumps(event))
    
    if fraud_reasons:
        return True, fraud_reasons
    else:
        return False, fraud_reasons

# Geração de relatório de fraude
def generate_fraud_report(event, fraud_reasons):
    timestamp_str = event['timestamp'].replace(':', '_').replace('-', '_').replace('T', '_').replace('Z', '')
    report_name = f"relatorio_fraude_{event['session_id']}_{timestamp_str}.txt"
    fraud_reasons_str = ', '.join(fraud_reasons)
    report_content = f"Requisição Considerada Fraudulenta:\nCategorias: {fraud_reasons_str}\nDetalhes:\n{json.dumps(event, indent=4)}"
    report_data = io.BytesIO(report_content.encode('utf-8'))
    report_size = report_data.getbuffer().nbytes
    return report_name, report_data, report_size


# Callback para processar as mensagens
def callback(ch, method, properties, body, redis_client):
    event = json.loads(body)
    fraudulent, fraud_reasons = is_fraudulent(event, redis_client)
    if fraudulent:
        print(f" [x] Requisição Fraudulenta Detectada")
        report_name, report_data, report_size = generate_fraud_report(event, fraud_reasons)
        save_pdf_to_minio(report_name, report_data, report_size)
    else:
        print(f" [x] Evento Processado")
    ch.basic_ack(delivery_tag=method.delivery_tag)

# Salvar PDF no MinIO
def save_pdf_to_minio(report_name, report_data, report_size):
    client = minio.Minio("minio:9000", access_key="admin", secret_key="admin1234", secure=False)
    bucket_name = "reportes-antifraude"
    client.put_object(bucket_name, report_name, report_data, report_size)
    report_url = client.get_presigned_url("GET", bucket_name, report_name)
    print(f" >>>> URL do Report:" + report_url.split('?')[0])

# Inicialização e execução do consumidor
def start_consumer(channel, redis_client):
    channel.basic_qos(prefetch_count=1)
    on_message_callback = lambda ch, method, properties, body: callback(ch, method, properties, body, redis_client)
    channel.basic_consume(queue='antifraud_queue', on_message_callback=on_message_callback, auto_ack=False)
    channel.start_consuming()

# Main
def main():
    connection = connect_rabbitmq()
    channel = connection.channel()
    redis_client = connect_redis()
    try:
        print('Consumidor iniciado...')
        start_consumer(channel, redis_client)
    except KeyboardInterrupt:
        channel.stop_consuming()
    connection.close()

if __name__ == "__main__":
    main()