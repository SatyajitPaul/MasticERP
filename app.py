import datetime
from flask import Flask, request, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_user import current_user, login_required, roles_required, UserManager, UserMixin

def makeAgents(db, email, User, Role, UserRoles):
    user = User.query.filter(User.email == email).first()
    agent = Role.query.filter(Role.name=='Agent').first()
    creatAgent = UserRoles(user_id=user.id, role_id=agent.id)
    db.session.add(creatAgent)
    db.session.commit()


# Class-based application configuration
class ConfigClass(object):
    """ Flask application config """

    # Flask settings
    SECRET_KEY = 'This is an INSECURE secret!! DO NOT use this in production!!'

    # Flask-SQLAlchemy settings
    SQLALCHEMY_DATABASE_URI = 'sqlite:///mastic_erp.sqlite'    # File-based SQL database
    SQLALCHEMY_TRACK_MODIFICATIONS = False    # Avoids SQLAlchemy warning

    # Flask-Mail SMTP server settings
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USE_TLS = False
    MAIL_USERNAME = 'email@example.com'
    MAIL_PASSWORD = 'password'
    MAIL_DEFAULT_SENDER = '"MyApp" <noreply@example.com>'

    # Flask-User settings
    USER_APP_NAME = "Flask-User Basic App"      # Shown in and email templates and page footers
    USER_ENABLE_EMAIL = True        # Enable email authentication
    USER_ENABLE_USERNAME = False    # Disable username authentication
    USER_EMAIL_SENDER_NAME = USER_APP_NAME
    USER_EMAIL_SENDER_EMAIL = "noreply@example.com"


def create_app():
    """ Flask application factory """
    
    # Create Flask app load app.config
    app = Flask(__name__)
    app.config.from_object(__name__+'.ConfigClass')


    # Initialize Flask-SQLAlchemy
    db = SQLAlchemy(app)

    # # Define the User data-model.
    # # NB: Make sure to add flask_user UserMixin !!!
    class User(db.Model, UserMixin):
        __tablename__ = 'users'
        id = db.Column(db.Integer, primary_key=True)
        active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')

        # User authentication information. The collation='NOCASE' is required
        # to search case insensitively when USER_IFIND_MODE is 'nocase_collation'.
        email = db.Column(db.String(255, collation='NOCASE'), nullable=False, unique=True)
        email_confirmed_at = db.Column(db.DateTime())
        password = db.Column(db.String(255), nullable=False, server_default='')

        # User information
        first_name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        last_name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')

        #Adress Details
        phone = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        adress = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        state = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        city = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        pin = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')

        # Define the relationship to Role via UserRoles
        roles = db.relationship('Role', secondary='user_roles')

    # Define the Role data-model
    class Role(db.Model):
        __tablename__ = 'roles'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(50), unique=True)

    # Define the UserRoles association table
    class UserRoles(db.Model):
        __tablename__ = 'user_roles'
        id = db.Column(db.Integer(), primary_key=True)
        user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
        role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

    # Setup Flask-User and specify the User data-model
    user_manager = UserManager(app, db, User)

    # # Create all database tables
    db.create_all()

    # # Create 'member@example.com' user with no roles
    # if not User.query.filter(User.email == 'member@example.com').first():
    #     user = User(
    #         email='member@example.com',
    #         email_confirmed_at=datetime.datetime.utcnow(),
    #         password=user_manager.hash_password('Password1'),
    #     )
    #     db.session.add(user)
    #     db.session.commit()

    # # Create 'admin@example.com' user with 'Admin' and 'Agent' roles
    # if not User.query.filter(User.email == 'admin@example.com').first():
    #     user = User(
    #         email='admin@example.com',
    #         email_confirmed_at=datetime.datetime.utcnow(),
    #         password=user_manager.hash_password('Password1'),
    #     )
    #     user.roles.append(Role(name='Admin'))
    #     user.roles.append(Role(name='Agent'))
    #     db.session.add(user)
    #     db.session.commit()
    
    # if not User.query.filter(User.email == 'agent@example.com').first():
        
    #     user = User(
    #         email='agent@example.com',
    #         email_confirmed_at=datetime.datetime.utcnow(),
    #         password=user_manager.hash_password('Password1'),
    #     )
    #     # user.roles.append(Role(name='Agent'))
    #     db.session.add(user)
    #     # role = UserRoles(user_id=user.id, role_id=agent_role.id)
    #     # db.session.add(role)
    #     db.session.commit()
    #     user_to_assigne = User.query.filter(User.email == 'agent@example.com').first()
    #     agent_role = Role(name='Agent')
    #     assigne_roles(db, user_to_assigne.id, agent_role.id)


    @app.route('/')
    def hello():
        return render_template('admin-base.html')

    @app.route('/table')
    def table():
        return render_template('table.html')

    @app.route('/add-employee',  methods=['GET', 'POST'])
    def add_employee():
        if request.method == 'POST':
            firstName = request.form.get('firstName')
            lastName = request.form.get('lastName')
            phone = request.form.get('phone')
            email = request.form.get('email')
            password = request.form.get('password')
            adress = request.form.get('adress')
            city = request.form.get('city')
            state = request.form.get('state')
            pin = request.form.get('pin')

            if not User.query.filter(User.email == email).first():
                user = User(
                    email=email,
                    email_confirmed_at=datetime.datetime.utcnow(),
                    password=user_manager.hash_password(password),
                    first_name=firstName,
                    last_name=lastName,
                    phone=phone,
                    adress=adress,
                    state=state,
                    city=city,
                    pin=pin,
                    )
                db.session.add(user)
                db.session.commit()

            makeAgents(db, email, User, Role, UserRoles)
            


            
            return redirect('/all-employee')
        else:
            return render_template('add-employee.html')

    @app.route('/all-employee')
    def all_employee():
        agent = User.query.filter(User.roles.has(Role(name='Agent')))
        return render_template('all-employee.html', agents=agent)

    @app.route('/admin/agent-delete/<id>')
    @roles_required('Admin')
    def deleteAgent(id):
        userToDelete = User.query.filter(User.id == id).first()
        db.session.delete(userToDelete)
        db.session.commit()
        return redirect('/all-employee')


    @app.route('/agent')    # @route() must always be the outer-most decorator
    @roles_required('Agent')
    def agentTest():
        return "Agent Working"

    return app


# Start development web server
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)

