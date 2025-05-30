import os
import smtplib
import logging
import hashlib
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText

import redis
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS

# --- Configuração de Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Carrega Variáveis de Ambiente ---
load_dotenv()
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
UPSTASH_REDIS_REST_URL = os.getenv('UPSTASH_REDIS_REST_URL')
CRON_SECRET = os.getenv('CRON_SECRET')

# --- Constantes ---
COUNT_KEY = 'portfolio:daily_access_count'
LOG_KEY = 'portfolio:daily_visit_log'

# --- Configuração do App Flask ---
app = Flask(__name__)
CORS(app)

# --- Conexão Redis ---
redis_client = None
if UPSTASH_REDIS_REST_URL:
    try:
        redis_client = redis.from_url(UPSTASH_REDIS_REST_URL, decode_responses=True)
        redis_client.ping()
        logging.info("Conectado ao Redis com sucesso!")
    except Exception as e:
        logging.error(f"Erro ao conectar ao Redis: {e}. Contagem desabilitada.")
        redis_client = None
else:
    logging.warning("UPSTASH_REDIS_REST_URL não definida. Contagem desabilitada.")

# --- Obter IP do Cliente ---
def get_client_ip(current_request):
    if 'fly-client-ip' in current_request.headers:
        return current_request.headers.get('fly-client-ip')
    if 'X-Forwarded-For' in current_request.headers:
        return current_request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return current_request.remote_addr

# Função para anonimizar IP
def anonymize_ip(ip):
    hashed = hashlib.sha256(ip.encode()).hexdigest()
    return hashed[:12]  # Usa só os 12 primeiros chars do hash

# --- Registrar Visita Única no Redis ---
def register_visit_in_redis():
    if not redis_client:
        logging.warning("Redis desabilitado, visita não registrada.")
        return False, 503

    raw_ip = get_client_ip(request)
    client_ip = anonymize_ip(raw_ip) if raw_ip else None

    if not client_ip:
        logging.warning("Não foi possível determinar o IP do cliente. Visita não rastreada como única.")
        return True, 200

    now_utc = datetime.now(timezone.utc)
    brt_offset = timedelta(hours=-3)
    brt_tz = timezone(brt_offset, name="BRT")
    now_brt = now_utc.astimezone(brt_tz)

    hour_str_for_log = now_brt.strftime('%H:%M')
    date_str_for_set = now_brt.strftime('%Y-%m-%d')

    unique_ips_key_today = f"portfolio:unique_ips:{date_str_for_set}"

    try:
        if redis_client.sadd(unique_ips_key_today, client_ip) == 1:
            pipe = redis_client.pipeline()
            pipe.hincrby(LOG_KEY, hour_str_for_log, 1)
            pipe.incr(COUNT_KEY)
            results = pipe.execute()

            # Expiração de 24h
            redis_client.expire(unique_ips_key_today, 86400)

            logging.info(
                f"NOVA visita ÚNICA registrada (IP hash: {client_ip}) às {hour_str_for_log}. Total de únicas hoje: {results[1]}"
            )
            return True, 204
        else:
            logging.info(
                f"Visita REPETIDA (IP hash: {client_ip}) às {hour_str_for_log}. Ignorando para contagem diária."
            )
            return True, 200

    except Exception as e:
        logging.error(f"Erro ao registrar visita única no Redis para IP {client_ip}: {e}")
        return False, 500

# --- Restante do código (sem alterações) ---
def send_email(count, log):
    if not all([EMAIL_ADDRESS, EMAIL_PASSWORD]):
        logging.error("Credenciais de email não configuradas. Email não enviado.")
        return False

    try:
        now_for_report_date = datetime.now(timezone.utc).astimezone(
            timezone(timedelta(hours=-3), name="BRT"))

        sorted_log_items = sorted(log.items())
        time_list_html = "<ul>" + "".join(
            f"<li>{hour} → {visits} visita(s)</li>" for hour, visits in sorted_log_items
        ) + "</ul>" if log else "<p>Nenhuma visita única registrada hoje.</p>"

        html_content = f"""
        <html>
            <body>
                <p>Hoje seu portfólio recebeu <strong>{count}</strong> visita(s) única(s)!</p>
                <p>Relatório diário de acessos - {now_for_report_date.strftime('%d/%m/%Y')}</p>
                <p><strong>Horários das primeiras visitas únicas (BRT):</strong></p>{time_list_html}
            </body>
        </html>
        """

        msg = MIMEText(html_content, 'html')
        msg['Subject'] = '📊 Relatório Diário de Visitas - Portfólio'
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = EMAIL_ADDRESS

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        logging.info(f"Relatório enviado com {count} visita(s) única(s).")
        return True
    except Exception as e:
        logging.error(f"Erro ao enviar relatório: {e}")
        return False

def process_report_request():
    if not redis_client:
        logging.error("Redis desabilitado, não é possível enviar relatório.")
        return {"message": "Redis desabilitado"}, 503

    try:
        count = int(redis_client.get(COUNT_KEY) or 0)
        log_raw = redis_client.hgetall(LOG_KEY)
        log = {hour: int(visits) for hour, visits in log_raw.items()}

        success = send_email(count, log)

        if success:
            redis_client.delete(COUNT_KEY, LOG_KEY)
            logging.info("Contadores de visitas únicas zerados após envio.")
            if count > 0:
                return {"message": f"Relatório enviado com {count} visita(s) única(s)."}, 200
            else:
                return {"message": "Relatório enviado. Nenhuma visita única registrada hoje."}, 200
        else:
            return {"message": "Erro ao enviar email. Contadores não foram zerados."}, 500

    except Exception as e:
        logging.error(f"Erro ao processar /send-report: {e}")
        return {"message": "Erro interno do servidor"}, 500

@app.route('/track-visit', methods=['GET', 'POST'])
def track_visit():
    success, status_code = register_visit_in_redis()
    return ("", status_code)

@app.route('/send-report', methods=['POST'])
def trigger_send_report():
    auth_header = request.headers.get('Authorization')
    expected_token = f"Bearer {CRON_SECRET}"

    if not CRON_SECRET:
        logging.warning("CRON_SECRET não definido. Permitindo acesso ao /send-report sem autenticação.")
    elif not auth_header or auth_header != expected_token:
        logging.warning(f"Tentativa de acesso não autorizado ao /send-report. Header: {auth_header}")
        return jsonify({"message": "Não Autorizado"}), 401

    response_data, status_code = process_report_request()
    return jsonify(response_data), status_code

if __name__ == '__main__':
    logging.info("Iniciando servidor Flask para desenvolvimento local...")
    app.run(host='0.0.0.0', port=5000, debug=True)
