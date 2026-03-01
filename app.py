import os
import smtplib
import logging
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText

import redis
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from user_agents import parse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

load_dotenv()
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
UPSTASH_REDIS_REST_URL = os.getenv('UPSTASH_REDIS_REST_URL')
CRON_SECRET = os.getenv('CRON_SECRET')

app = Flask(__name__)
CORS(app)

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


def identificar_bot(user_agent_string):
    if not user_agent_string:
        return True

    user_agent = parse(user_agent_string)
    ua_lower = user_agent_string.lower()

    if user_agent.is_bot or 'bot' in ua_lower:
        return True

    return False


def send_email(count, log, report_date_to_display):
    if not all([EMAIL_ADDRESS, EMAIL_PASSWORD]):
        return False

    try:
        sorted_log_items = sorted(log.items())

        if log:
            time_list_html = (
                    "<ul>" +
                    "".join(
                        f"<li>{hour} - {visits} visualização{'es' if int(visits) > 1 else ''}</li>"
                        for hour, visits in sorted_log_items
                    ) +
                    "</ul>"
            )
        else:
            time_list_html = "<p>Nenhuma visualização registrada neste dia.</p>"

        report_date_str = report_date_to_display.strftime('%d/%m/%Y')

        html_content = f"""
        <html>
            <body>
                <h2>Relatório Portfólio - {report_date_str}</h2>
                <p>Confira as métricas de acesso do seu portfólio:</p>
                <p><strong>Total de visualizações:</strong> {count}</p>
                <p><strong>Distribuição por horário:</strong></p>
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

        return True

    except Exception as ex:
        logging.error(f"Erro ao enviar relatório: {ex}")
        return False


def register_visit_in_redis():
    user_agent_string = request.headers.get('User-Agent')

    if not user_agent_string or identificar_bot(user_agent_string):
        return True, 200

    if not redis_client:
        return False, 503

    now_utc = datetime.now(timezone.utc)
    brt_offset = timedelta(hours=-3)
    brt_tz = timezone(brt_offset, name="BRT")
    now_brt = now_utc.astimezone(brt_tz)

    date_str = now_brt.strftime('%Y-%m-%d')
    hour_str = now_brt.strftime('%H:%M')

    count_key = f"portfolio:count:{date_str}"
    log_key = f"portfolio:log:{date_str}"

    ttl_seconds = 172800

    try:
        pipe = redis_client.pipeline()
        pipe.incr(count_key)
        pipe.hincrby(log_key, hour_str, 1)
        pipe.expire(count_key, ttl_seconds)
        pipe.expire(log_key, ttl_seconds)
        results = pipe.execute()

        logging.info(f"Visualização registrada: {date_str} {hour_str}. Total do dia: {results[0]}")
        return True, 204
    except Exception as ex:
        logging.error(f"Erro ao registrar visualização: {ex}")
        return False, 500


def process_report_request():
    brt_tz = timezone(timedelta(hours=-3), name="BRT")
    current_job_run_brt = datetime.now(timezone.utc).astimezone(brt_tz)
    report_target_date = current_job_run_brt - timedelta(days=1)
    report_target_date_str = report_target_date.strftime('%Y-%m-%d')

    count_key = f"portfolio:count:{report_target_date_str}"
    log_key = f"portfolio:log:{report_target_date_str}"

    if not redis_client:
        return {"message": "Redis desabilitado"}, 503
    try:
        count = int(redis_client.get(count_key) or 0)
        log_raw = redis_client.hgetall(log_key)
        log = {hour: int(visits) for hour, visits in log_raw.items()}

        success = send_email(count, log, report_target_date)
        if success:
            return {"message": f"Relatório de {report_target_date_str} enviado com sucesso."}, 200
        else:
            return {"message": "Falha ao enviar o e-mail do relatório."}, 500
    except Exception as ex:
        logging.error(f"Erro no processamento do relatório: {ex}")
        return {"message": "Erro interno no servidor."}, 500


@app.route('/track-visit', methods=['GET'])
def track_visit():
    success, status_code = register_visit_in_redis()
    return "", status_code


@app.route('/send-report', methods=['POST'])
def trigger_send_report():
    auth_header = request.headers.get('Authorization')
    expected_token = f"Bearer {CRON_SECRET}"
    if CRON_SECRET and (not auth_header or auth_header != expected_token):
        return jsonify({"message": "Não Autorizado"}), 401
    response_data, status_code = process_report_request()
    return jsonify(response_data), status_code


if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port)