# Portfolio Notification

## PT-BR

Projeto desenvolvido em **Python** para monitorar e notificar a quantidade de visualizações no meu [portfólio pessoal](https://marllonmendez.vercel.app/pt-br). 

O sistema funciona como um microsserviço de análise ultra-leve, contabilizando acessos em tempo real e enviando relatórios diários via e-mail.

### Tecnologias Utilizadas

- **Linguagem:** Python 3.14.3
- **Framework Web:** Flask
- **Servidor de Produção:** Gunicorn (com suporte a threads)
- **Banco de Dados (Cache):** Redis (via [Upstash](https://upstash.com/))
- **Containerização:** Docker
- **Plataforma de Hospedagem:** [Render](https://render.com/)

### Funcionalidades

- **Contagem Anônima:** Contabiliza cada visualização de forma totalmente anônima, sem armazenar IPs, IDs ou hashes.
- **Filtro de Bots:** Identificação e descarte automático de acessos vindos de web crawlers e bots de busca para manter métricas reais.
- **Relatórios Automáticos (e-mail):**
  - Total de visualizações do dia anterior.
  - Log detalhado de acessos distribuídos por faixa horária.
- **Gestão de Recursos:** Limpeza automática de dados no Redis a cada 48h para otimização do plano gratuito.

### Variáveis de Ambiente

| Variável                   | Descrição                                               |
|----------------------------|---------------------------------------------------------|
| `EMAIL_ADDRESS`            | Endereço de e-mail que enviará e receberá o relatório.  |
| `EMAIL_PASSWORD`           | Senha de aplicativo do e-mail (SMTP).                   |
| `UPSTASH_REDIS_REST_URL`   | URL de conexão com o Redis.                             |
| `CRON_SECRET`              | Token de segurança para validar o disparo do relatório. |
| `SMTP_SERVER`              | Servidor SMTP (ex: smtp.gmail.com).                     |

### Privacidade e Transparência

Este projeto foi construído focando na privacidade total do usuário. **Não coletamos, processamos ou armazenamos dados pessoais.** O sistema apenas incrementa contadores numéricos no banco de dados. Como nenhum dado identificável (como IP) é lido ou gravado, o projeto está intrinsecamente em conformidade com as diretrizes da LGPD.

---

## EN

Project developed in **Python** to monitor and notify the number of views on my [personal portfolio](https://marllonmendez.vercel.app/en).

The system works as an ultra-lightweight analytics microservice, counting real-time views and sending daily reports via email.

### Technologies Used

* **Language:** Python 3.14.3
* **Web Framework:** Flask
* **Production Server:** Gunicorn (with thread support)
* **Database (Cache):** Redis (via [Upstash](https://upstash.com/))
* **Containerization:** Docker
* **Hosting Platform:** [Render](https://render.com/)

### Features

* **Anonymous Counting:** Counts every view completely anonymously, without storing IPs, IDs, or hashes.
* **Bot Filtering:** Automatic detection and exclusion of traffic from web crawlers and search bots to keep metrics accurate.
* **Automated Reports (Email):**
  * Total views from the previous day.
  * Detailed access logs distributed by time range.
* **Resource Management:** Automatic cleanup of Redis data every 48 hours to optimize usage under the free plan.

### Environment Variables

| Variable                   | Description                                         |
|----------------------------|-----------------------------------------------------|
| `EMAIL_ADDRESS`            | Email address used to send and receive the report.  |
| `EMAIL_PASSWORD`           | App-specific email password (SMTP).                 |
| `UPSTASH_REDIS_REST_URL`   | Redis connection URL.                               |
| `CRON_SECRET`              | Security token to validate the report trigger.      |
| `SMTP_SERVER`              | SMTP server (e.g., smtp.gmail.com).                 |

### Privacy & Transparency

This project was built with a focus on total user privacy. **We do not collect, process, or store personal data.** The system only increments numerical counters in the database. Since no identifiable data (such as IP) is read or recorded, the project is intrinsically compliant with privacy regulations like LGPD/GDPR.