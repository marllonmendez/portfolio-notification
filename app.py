import os
import smtplib
import logging
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
import hashlib

import redis
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from user_agents import parse

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
    except Exception as ex:
        logging.error(f"Erro ao conectar ao Redis: {ex}.")
        redis_client = None
else:
    logging.warning("UPSTASH_REDIS_REST_URL não definida.")


# --- Funções Auxiliares ---
def get_client_ip(current_request):
    if 'fly-client-ip' in current_request.headers:
        return current_request.headers.get('fly-client-ip')
    if 'X-Forwarded-For' in current_request.headers:
        return current_request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return current_request.remote_addr


def identificar_bot(user_agent_string):
    if not user_agent_string:
        return True

    user_agent = parse(user_agent_string)
    ua_lower = user_agent_string.lower()

    is_lib_bot = user_agent.is_bot
    is_string_bot = 'bot' in ua_lower

    if is_lib_bot:
        logging.info("Bot detectado.")
        return True
    if is_string_bot:
        logging.info("Bot detectado.")
        return True

    return False



# --- Funções Principais ---
def send_email(count, log, report_date_to_display):
    if not all([EMAIL_ADDRESS, EMAIL_PASSWORD]):
        logging.error("Credenciais de email não configuradas. Email não enviado!")
        return False

    try:
        sorted_log_items = sorted(log.items())

        if log:
            time_list_html = (
                "<ul>" +
                "".join(
                    f"<li>{hour} - {visits} visita{'s' if visits > 1 else ''}</li>"
                    for hour, visits in sorted_log_items
                ) +
                "</ul>"
            )
        else:
            time_list_html = "<p>Nenhuma visita registrada neste dia.</p>"

        report_date_str = report_date_to_display.strftime('%d/%m/%Y')

        html_content = f"""
        <html>
            <body>
                <h2>Relatório Portfólio - {report_date_str}</h2>
                <p>Confira os acessos recebidos no portfólio neste dia:</p>
                <p><strong>Total de visitas:</strong> {count}</p>
                <p><strong>Horários de acesso:</strong></p>
                {time_list_html}
            </body>
        </html>
        """

        msg = MIMEText(html_content, 'html')
        msg['Subject'] = f"Relatório Portfólio - {report_date_str}"
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = EMAIL_ADDRESS

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)

        logging.info(f"Relatório de visita(s) para {report_date_str} enviado com {count} visita(s).")
        return True

    except Exception as ex:
        logging.error(f"Erro ao enviar relatório para {report_date_to_display.strftime('%d/%m/%Y')}: {ex}")
        return False


def register_visit_in_redis():
    user_agent_string = request.headers.get('User-Agent')
    client_ip = get_client_ip(request)

    hashed_ip = 'N/D'
    if client_ip:
        try:
            hashed_ip = hashlib.sha256(client_ip.encode('utf-8')).hexdigest()
        except Exception as ex:
            logging.error(f"Falha ao gerar hash para o IP: {ex}")

    if not user_agent_string:
        logging.info("Requisição sem User-Agent, tratando como bot.")
        return True, 200

    if identificar_bot(user_agent_string):
        logging.info("Acesso de bot IGNORADO.")
        return True, 200

    if not redis_client:
        logging.warning("Redis desabilitado, visita não registrada!")
        return False, 503

    if hashed_ip == 'N/D':
        logging.warning("Não foi possível determinar o IP do cliente ou houve falha no hash. Visita não rastreada por IP.")
        return True, 200

    now_utc = datetime.now(timezone.utc)
    brt_offset = timedelta(hours=-3)
    brt_tz = timezone(brt_offset, name="BRT")
    now_brt = now_utc.astimezone(brt_tz)

    hour_str_for_log = now_brt.strftime('%H:%M')
    date_str_for_keys = now_brt.strftime('%Y-%m-%d')

    unique_ips_key_current_day = f"portfolio:unique_ips:{date_str_for_keys}"
    count_key_current_day = f"portfolio:count:{date_str_for_keys}"
    log_key_current_day = f"portfolio:log:{date_str_for_keys}"

    ttl_seconds = 86400

    try:
        if redis_client.sadd(unique_ips_key_current_day, hashed_ip) == 1:
            pipe = redis_client.pipeline()
            pipe.incr(count_key_current_day)
            pipe.hincrby(log_key_current_day, hour_str_for_log, 1)
            results = pipe.execute()

            redis_client.expire(unique_ips_key_current_day, ttl_seconds)
            redis_client.expire(count_key_current_day, ttl_seconds)
            redis_client.expire(log_key_current_day, ttl_seconds)

            logging.info(f"Nova visita registrada. Data BRT: {date_str_for_keys} {hour_str_for_log}. Total: {results[0]}")
            return True, 204
        else:
            logging.info(f"Visita repetida ignorada. Data BRT: {date_str_for_keys} {hour_str_for_log}.")
            return True, 200
    except Exception as ex:
        logging.error(f"Erro ao registrar visita. Data: {date_str_for_keys}")
        return False, 500



def process_report_request():
    brt_tz = timezone(timedelta(hours=-3), name="BRT")
    current_job_run_brt = datetime.now(timezone.utc).astimezone(brt_tz)
    report_target_date = current_job_run_brt - timedelta(days=1)
    report_target_date_str = report_target_date.strftime('%Y-%m-%d')

    count_key_for_report = f"portfolio:count:{report_target_date_str}"
    log_key_for_report = f"portfolio:log:{report_target_date_str}"

    if not redis_client:
        logging.error("Redis desabilitado, não é possível enviar relatório.")
        return {"message": "Redis desabilitado"}, 503
    try:
        count = int(redis_client.get(count_key_for_report) or 0)
        log_raw = redis_client.hgetall(log_key_for_report)
        log = {hour: int(visits) for hour, visits in log_raw.items()}

        success = send_email(count, log, report_target_date)
        if success:
            logging.info(
                f"Relatório para {report_target_date_str} enviado. As chaves expirarão em 24h.")
            message = f"Relatório para {report_target_date_str} enviado. "
            message += f"{count} visita(s) registrada(s)." if count > 0 else "Nenhuma visita registrada."
            return {"message": message}, 200
        else:
            return {"message": f"Erro ao enviar email para o relatório de {report_target_date_str}."}, 500
    except Exception as ex:
        logging.error(f"Erro ao processar /send-report para {report_target_date_str}: {ex}")
        return {"message": "Erro interno do servidor ao processar o relatório."}, 500


# --- Rotas da API ---
@app.route('/track-visit', methods=['GET'])
def track_visit():
    success, status_code = register_visit_in_redis()
    return "", status_code


@app.route('/send-report', methods=['POST'])
def trigger_send_report():
    auth_header = request.headers.get('Authorization')
    expected_token = f"Bearer {CRON_SECRET}"
    if CRON_SECRET and (not auth_header or auth_header != expected_token):
        logging.warning("Tentativa de acesso não autorizado ao /send-report.")
        return jsonify({"message": "Não Autorizado"}), 401
    response_data, status_code = process_report_request()
    return jsonify(response_data), status_code


# --- Execução para Teste Local ---
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    logging.info(f"Iniciando servidor Flask para desenvolvimento local na porta {port}...")
    app.run(host='0.0.0.0', port=port, debug=True)
