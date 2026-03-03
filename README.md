# Portfolio Notification

## PT-BR

Projeto desenvolvido em **Python** para monitorar e notificar a quantidade de visualizações no meu [portfólio pessoal](https://marllonmendez.vercel.app/pt-br).

O sistema funciona como um microsserviço de análise **ultra-leve e seguro**, contabilizando acessos reais em tempo quase real e enviando **relatórios diários por e-mail**, sem coleta de dados pessoais.

### Tecnologias Utilizadas

- **Linguagem:** Python 3
- **Framework Web:** Flask
- **Servidor de Produção:** Gunicorn (com suporte a threads)
- **Banco de Dados (Cache):** Redis (via [Upstash](https://upstash.com/))
- **Template Engine:** Jinja2 (HTML/CSS Dinâmico)
- **Containerização:** Docker
- **Serviço de E-mail:** [Resend](https://resend.com/)
- **Plataforma de Hospedagem:** [Render](https://render.com/)

### Funcionalidades

- **Contagem Anônima de Visitas**
  - Nenhum IP, cookie, fingerprint ou identificador persistente é armazenado.
  - Apenas contadores numéricos agregados são persistidos no Redis.

- **Filtro Automático de Bots**
  - Identificação de bots e crawlers via análise de User-Agent.
  - Acessos identificados como bots são descartados automaticamente.

- **Proteção contra Abuso**
  - Validação de domínio de origem (`Origin` / `Referer`).
  - Autenticação opcional via token customizado (`X-Track-Token`).
  - Bloqueio explícito de requisições não autorizadas.

- **Relatórios Diários via E-mail**
  - Relatório automático referente ao **dia anterior**.
  - Total de visitas agregadas.
  - Distribuição de acessos por faixa horária.
  - Template HTML renderizado com Jinja2.
  - Envio realizado via Resend.

- **Gerenciamento de Recursos**
  - TTL automático de 48 horas para chaves no Redis.
  - Projeto otimizado para planos gratuitos.

### Endpoints

#### `POST /track-visit`

Endpoint responsável por registrar uma visita válida.

Regras:
- Origem deve pertencer ao domínio autorizado.
- Token de rastreamento deve ser válido (quando configurado).
- Bots são ignorados automaticamente.

Headers esperados:
- `Origin` ou `Referer`
- `User-Agent`
- `X-Track-Token` (opcional, se habilitado)

---

#### `POST /send-report`

Endpoint responsável por gerar e enviar o relatório diário.

- Protegido por autenticação via **Bearer Token**.
- Deve ser acionado por um job externo (cron, pipeline, scheduler).

Header obrigatório:
- `Authorization: Bearer <CRON_SECRET>`

### Fluxo de Funcionamento

1. O front-end do portfólio envia um `POST` para `/track-visit`.
2. O serviço valida domínio, token e User-Agent.
3. Visitas válidas são agregadas no Redis por data e horário.
4. Um job externo executa um `POST` em `/send-report`.
5. O relatório do dia anterior é gerado e enviado por e-mail.

### Variáveis de Ambiente

| Variável                 | Descrição                                                                |
|--------------------------|--------------------------------------------------------------------------|
| `RESEND_API_KEY`         | Chave de API do serviço Resend.                                          |
| `EMAIL_TO`               | Endereço de e-mail que receberá o relatório.                             |
| `RESEND_FROM`            | E-mail remetente utilizado no envio.                                     |
| `UPSTASH_REDIS_REST_URL` | URL de conexão com o Redis (Upstash).                                    |
| `CRON_SECRET`            | Token Bearer para autenticar o envio do relatório.                       |
| `TRACK_TOKEN`            | Token opcional para autenticar o endpoint de tracking.                   |
| `ALLOWED_DOMAIN`         | Domínio autorizado a registrar visitas.                                  |
| `PORT`                   | Porta de execução da aplicação (default: 8080).                          |

### Segurança

- Validação explícita de domínio de origem.
- Autenticação por token no tracking e no disparo de relatórios.
- Nenhum dado sensível do visitante é coletado ou persistido.

### Privacidade e Transparência

Este projeto foi construído com foco absoluto em privacidade.

**Nenhum dado pessoal é coletado, processado ou armazenado.**  
O sistema opera exclusivamente com **contadores agregados**, sem qualquer forma de identificação do usuário final.

Por não lidar com dados pessoais, o projeto está alinhado às diretrizes da **LGPD**.

---

## EN

Project developed in **Python** to monitor and notify the number of views on my [personal portfolio](https://marllonmendez.vercel.app/en).

The system works as a **secure ultra-lightweight analytics microservice**, counting real visits and sending **daily email reports**, without collecting personal data.

### Technologies Used

- **Language:** Python 3
- **Web Framework:** Flask
- **Production Server:** Gunicorn (with thread support)
- **Database (Cache):** Redis (via [Upstash](https://upstash.com/))
- **Template Engine**: Jinja2 (Dynamic HTML/CSS)
- **Containerization:** Docker
- **Email Service:** [Resend](https://resend.com/)
- **Hosting Platform:** [Render](https://render.com/)

### Features

- **Anonymous Visit Counting**
  - No IPs, cookies, fingerprints, or user identifiers are stored.
  - Only aggregated numeric counters are persisted.

- **Bot Filtering**
  - Automatic bot and crawler detection via User-Agent analysis.
  - Bot traffic is ignored.

- **Abuse Protection**
  - Allowed domain validation.
  - Optional tracking token authentication.
  - Explicit request blocking when validation fails.

- **Daily Email Reports**
  - Report generated for the previous day.
  - Total visit count and time-based distribution.
  - HTML email rendered with Jinja2.
  - Delivery handled by Resend.

- **Resource Management**
  - Redis keys expire automatically after 48 hours.

### Environment Variables

| Variable                 | Description                                                              |
|--------------------------|--------------------------------------------------------------------------|
| `RESEND_API_KEY`         | Resend API key.                                                          |
| `EMAIL_TO`               | Email address that will receive the report.                              |
| `RESEND_FROM`            | Sender email used by Resend.                                             |
| `UPSTASH_REDIS_REST_URL` | Redis connection URL (Upstash).                                          |
| `CRON_SECRET`            | Bearer token to trigger the report endpoint.                             |
| `TRACK_TOKEN`            | Optional token to authenticate tracking requests.                        |
| `ALLOWED_DOMAIN`         | Authorized domain for visit tracking.                                    |
| `PORT`                   | Application port (default: 8080).                                        |

### Privacy & Transparency

This project was built with a strict privacy-first approach.

**No personal data is collected, processed, or stored.**  
The system operates exclusively with aggregated counters, making it inherently compliant with **LGPD** guidelines.