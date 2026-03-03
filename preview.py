import os
from jinja2 import Environment, FileSystemLoader

def generate_preview():
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report.html')
    mock_data = {
        "data_relatorio": "02/03/2026",
        "total_visitas": 124,
        "log_itens": [
            ("08:00", 10),
            ("12:00", 45),
            ("18:30", 50),
            ("22:15", 19)
        ],
        "ano_atual": 2026,
    }
    html_content = template.render(**mock_data)
    with open("email_preview.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    print("Preview gerado! Abra 'email_preview.html' para validar o novo rodapé.")

if __name__ == "__main__":
    generate_preview()