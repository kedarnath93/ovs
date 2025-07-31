from flask import Flask, render_template, flash, redirect, url_for, session
from webforms import LoginForm, UserForm, VoteEventForm, CloseEventForm, CastVoteForm
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from prometheus_client import Counter, Histogram, start_http_server, generate_latest
import time

# Create a Flask Instance
app = Flask(__name__)
DB_NAME = "database.db"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_NAME
app.config['SECRET_KEY'] = secrets.token_urlsafe(16)

# Prometheus Metrics
REQUEST_COUNT = Counter(
    'http_requests_total', 'Total number of HTTP requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds', 'Histogram for the duration of HTTP requests in seconds',
    ['method', 'endpoint']
)

# DB migration metadata naming constraints
convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}
metadata = MetaData(naming_convention=convention)

db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db)

# Flask_Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Prometheus Metrics Route
@app.route('/metrics')
def metrics():
    return generate_latest()

# Create a route decorator
@app.route('/')
def index():
    start_time = time.time()

    # Simulate processing logic (replace this with actual logic)
    time.sleep(1)

    # Record the request count and latency
    REQUEST_COUNT.labels(method='GET', endpoint='/', status_code='200').inc()
    REQUEST_LATENCY.labels(method='GET', endpoint='/').observe(time.time() - start_time)

    return render_template("index.html")

# Create Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    start_time = time.time()
    form = LoginForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                session['id'] = user.id
                session['firstname'] = user.firstname
                # Record metrics for successful login
                REQUEST_COUNT.labels(method='POST', endpoint='/login', status_code='200').inc()
                REQUEST_LATENCY.labels(method='POST', endpoint='/login').observe(time.time() - start_time)
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong Password - Try Again!")
        else:
            flash("That User Doesn't Exist! Try Again...")
    
    # Track failed login attempt
    REQUEST_COUNT.labels(method='POST', endpoint='/login', status_code='400').inc()
    REQUEST_LATENCY.labels(method='POST', endpoint='/login').observe(time.time() - start_time)

    return render_template('login.html', form=form)

# Create Logout Page
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    start_time = time.time()
    logout_user()
    session.pop('id', default=None)
    session.pop('firstname', default=None)
    flash("You Have Been Logged Successfully Out!")
    
    # Record logout action
    REQUEST_COUNT.labels(method='GET', endpoint='/logout', status_code='200').inc()
    REQUEST_LATENCY.labels(method='GET', endpoint='/logout').observe(time.time() - start_time)

    return redirect(url_for('login'))

# More Routes...
# Each route can similarly be instrumented with REQUEST_COUNT and REQUEST_LATENCY as shown in the login and logout routes.

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

# Create Model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    firstname = db.Column(db.String(200), nullable=False)
    lastname = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    gender = db.Column(db.String(10), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute!')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Name %r>' % self.name

# Create a Participants model
class Participants(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    votecount = db.Column(db.Integer, default=0)
    voteevent = db.Column(db.Integer, db.ForeignKey('voteevent.id'))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

# Create a Voteevent model
class Voteevent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    status = db.Column(db.String(255), nullable=False, default='open')
    description = db.Column(db.Text)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))

# Create a Voteeventuser model
class Voteeventuser(db.Model):
    id = db.Column(db.Integer, primary_key=True)    
    user = db.Column(db.Integer, db.ForeignKey('users.id'))
    voteevent = db.Column(db.Integer, db.ForeignKey('voteevent.id'))
    uservoted = db.Column(db.String(10), nullable=False, default='False')

if __name__ == '__main__':
    # Start the Prometheus metrics server on port 8000
    start_http_server(8000)  # This exposes the metrics endpoint to Prometheus
    app.run(host='0.0.0.0', port=5000)
