from . import app


def send_w_mailgun(subject, recipient, template):
    return requests.post(
        "https://api.mailgun.net/v2/onename.io/messages",
        auth=("api", app.config['MAILGUN_API_KEY']),
        data={
            "from": app.config['MAIL_USERNAME'],
            "to": recipient,
            "subject": subject,
            "html": template
        }
    )
