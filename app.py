import logging
import os
import resend
from datetime import datetime, timedelta, timezone
import redis
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from user_agents import parse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

load_dotenv()
RESEND_API_KEY = os.getenv('RESEND_API_KEY')
EMAIL_TO = os.getenv('EMAIL_TO')
RESEND_FROM = os.getenv('RESEND_FROM')
UPSTASH_REDIS_REST_URL = os.getenv('UPSTASH_REDIS_REST_URL')
CRON_SECRET = os.getenv('CRON_SECRET')
TRACK_TOKEN = os.getenv('TRACK_TOKEN')
ALLOWED_DOMAIN = os.getenv('ALLOWED_DOMAIN')

if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY

app = Flask(__name__)
CORS(app)

redis_client = None
if UPSTASH_REDIS_REST_URL:
    try:
        redis_client = redis.from_url(
            UPSTASH_REDIS_REST_URL,
            decode_responses=True,
            health_check_interval=30
        )
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
    if not all([RESEND_API_KEY, EMAIL_TO, RESEND_FROM]):
        logging.error(f"Configurações do Resend ausentes -> API_KEY: {bool(RESEND_API_KEY)}, EMAIL_TO: {bool(EMAIL_TO)}, RESEND_FROM: {bool(RESEND_FROM)}")
        return False
    
    resend.api_key = RESEND_API_KEY
    try:
        report_date_str = report_date_to_display.strftime('%d/%m/%Y')
        sorted_log_items = sorted(log.items())
        with app.app_context():
            html_content = render_template(
                'report.html',
                data_relatorio=report_date_str,
                total_visitas=count,
                log_itens=sorted_log_items
            )

        params = {
            "from": f"Relatórios <{RESEND_FROM}>",
            "to": [EMAIL_TO],
            "subject": f"Relatório de Acessos - {report_date_str}",
            "html": html_content
        }

        resend.Emails.send(params)
        return True
    except Exception as ex:
        logging.error(f"Erro ao enviar relatório via Resend: {ex}")
        return False


def register_visit_in_redis():
    origin = request.headers.get('Origin') or request.headers.get('Referer')
    if not origin or ALLOWED_DOMAIN not in origin:
        logging.warning(f"Acesso bloqueado: Origem não autorizada ({origin})")
        return False, 403

    if TRACK_TOKEN:
        auth_token = request.headers.get('X-Track-Token')
        if auth_token != TRACK_TOKEN:
            logging.warning("Acesso bloqueado: Token de rastreamento inválido.")
            return False, 401

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
        pipe.execute()
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


@app.route('/track-visit', methods=['POST'])
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