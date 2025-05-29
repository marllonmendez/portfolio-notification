import os
import smtplib
import logging
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


# --- Funções Principais ---
def send_email(count, log):
    # Prepara e envia o e-mail de relatório diário.
    if not all([EMAIL_ADDRESS, EMAIL_PASSWORD]):
        logging.error("Credenciais de email não configuradas. Email não enviado.")
        return False

    try:
        # A data aqui será a data do servidor (UTC) quando o email for enviado
        # mas os horários no 'log' já estarão em BRT.
        now_for_report_date = datetime.now()
        time_list_html = "<ul>" + "".join(
            f"<li>{hour} → {visits} visita(s)</li>" for hour, visits in sorted(log.items())
        ) + "</ul>" if log else "<p>Nenhuma visita registrada hoje.</p>"

        html_content = f"""
        <html>
            <body>
                <p>Hoje seu portfólio recebeu <strong>{count}</strong> visita(s)!</p>
                <p>Relatório diário de acessos - {now_for_report_date.strftime('%d/%m/%Y')}</p>
                <p><strong>Horários das visitas (BRT):</strong></p>{time_list_html} 
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
        logging.info(f"Relatório enviado com {count} acesso(s).")
        return True
    except Exception as e:
        logging.error(f"Erro ao enviar relatório: {e}")
        return False


def register_visit_in_redis():
    # Registra uma visita no Redis, convertendo a hora para BRT.
    if not redis_client:
        logging.warning("Redis desabilitado, visita não registrada.")
        return False, 503

    # 1. Pega a hora atual em UTC (horário do servidor Fly.io)
    now_utc = datetime.now(timezone.utc)

    # 2. Define o offset para BRT (UTC-3)
    brt_offset = timedelta(hours=-3)
    brt_tz = timezone(brt_offset, name="BRT")

    # 3. Converte a hora UTC para BRT
    now_brt = now_utc.astimezone(brt_tz)

    # 4. Formata a hora BRT para salvar no Redis
    hour_str = now_brt.strftime('%H:%M')

    try:
        pipe = redis_client.pipeline()
        pipe.hincrby(LOG_KEY, hour_str, 1)
        pipe.incr(COUNT_KEY)
        results = pipe.execute()
        logging.info(f"Visita registrada (BRT: {hour_str}). Total no Redis: {results[1]}")
        return True, 204
    except Exception as e:
        logging.error(f"Erro ao registrar visita no Redis: {e}")
        return False, 500


def process_report_request():
    # Busca dados, envia email e limpa Redis.
    if not redis_client:
        logging.error("Redis desabilitado, não é possível enviar relatório.")
        return {"message": "Redis desabilitado"}, 503

    try:
        count = int(redis_client.get(COUNT_KEY) or 0)
        log_raw = redis_client.hgetall(LOG_KEY)
        log = {hour: int(visits) for hour, visits in log_raw.items()}

        if count > 0:
            success = send_email(count, log)
            if success:
                redis_client.delete(COUNT_KEY, LOG_KEY)
                logging.info("Contadores do Redis zerados após envio.")
                return {"message": f"Relatório enviado com {count} visitas."}, 200
            else:
                return {"message": "Erro ao enviar email."}, 500
        else:
            logging.info("Nenhuma visita para reportar.")
            redis_client.delete(COUNT_KEY, LOG_KEY)
            return {"message": "Nenhuma visita para reportar."}, 200
    except Exception as e:
        logging.error(f"Erro ao processar /send-report: {e}")
        return {"message": "Erro interno do servidor"}, 500


# --- Rotas da API ---
@app.route('/track-visit', methods=['GET', 'POST'])
def track_visit():
    # Endpoint para registrar uma visita.
    success, status_code = register_visit_in_redis()
    return ("", status_code) if success else ("Erro", status_code)


@app.route('/send-report', methods=['POST'])
def trigger_send_report():
    # Endpoint seguro para o Cron Job chamar.
    auth_header = request.headers.get('Authorization')
    expected_token = f"Bearer {CRON_SECRET}"

    if not CRON_SECRET or not auth_header or auth_header != expected_token:
        logging.warning("Tentativa de acesso não autorizado ao /send-report.")
        return "Não Autorizado", 401

    response_data, status_code = process_report_request()
    return jsonify(response_data), status_code


# --- Execução para Teste Local ---
if __name__ == '__main__':
    logging.info("Iniciando servidor Flask para desenvolvimento local...")
    app.run(host='0.0.0.0', port=5000, debug=True)