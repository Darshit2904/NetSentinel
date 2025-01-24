from flask_mail import Mail, Message

def create_mail(app):
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USERNAME'] = 'netsentinelsecure@gmail.com'
    app.config['MAIL_PASSWORD'] = 'hogi rdxm fyki atka'
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True

    mail = Mail(app)
    return mail

def send_email(mail, app, name, user_email, message_body):
    logo_path = 'static/logo.png'  

    
    msg_to_company = Message(f"Message from {name}", 
                              sender='netsentinelsecure@gmail.com',
                              recipients=['netsentinelsecure@gmail.com'])
    msg_to_company.body = f"From: {name} ({user_email})\n\nMessage:\n{message_body}"
    mail.send(msg_to_company)

    msg_to_user = Message("Thank You for Contacting Us!", 
                          sender='netsentinelsecure@gmail.com',
                          recipients=[user_email])


    msg_to_user.html = f"""
    <p>Dear {name},</p>
    <p>Thank you for reaching out to us. We appreciate your interest and will get back to you shortly.</p>
    <p>Best Regards,<br>Netsentinel Team</p>
    <div style="margin-top: 20px;">
        <div style="display: flex; align-items: center;">
            <img src="cid:logo" alt="Netsentinel Logo" style="width: 100px; height: auto; margin-right: 10px;">
            <div>
                <h2 style="margin: 0; color: black;">Netsentinel</h2>
                <p style="margin: 0; color: gray;">Scan. Detect. Protect.</p>
            </div>
        </div>
    </div>
    """

    try:
        with app.open_resource(logo_path) as img:
            msg_to_user.attach("logo.png", "image/png", img.read(), headers={"Content-ID": "<logo>"})
    except Exception as e:
        print(f"Error attaching logo: {e}")

    mail.send(msg_to_user)
