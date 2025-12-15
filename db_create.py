from app import create_app
from models import db, User

app = create_app()
with app.app_context():
    db.create_all()
    # optional: create a test user
    if not User.query.filter_by(username='test').first():
        u = User(username='test')
        u.set_password('Test@12345')
        db.session.add(u)
        db.session.commit()
        print("Created test user: username='test', password='Test@12345'")
    else:
        print("Test user already exists")
