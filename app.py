import secrets
from flask import Flask, request, redirect, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
# TODO unify login for all services
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
app.config["SECRET_KEY"] = secrets.token_hex()
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
admin = Admin(app, name='DevDrip', template_mode='bootstrap3')



class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=80)])
    link = StringField('Link', validators=[DataRequired(), Length(max=120)])


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    link = db.Column(db.String(120), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Upvote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Post, db.session))
admin.add_view(ModelView(Comment, db.session))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    form = PostForm()
    page = request.args.get('page', 1, type=int)
    posts = Post.query.paginate(page=1, per_page=10)
    return render_template('index.html', posts=posts.items, next_url=url_for('index', page=posts.next_num), prev_url=url_for('index', page=posts.prev_num), form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/post', methods=['POST'])
@login_required
def post():
    title = request.form['title']
    link = request.form['link']
    new_post = Post(title=title, link=link)
    db.session.add(new_post)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/post/<int:post_id>')
def post_page(post_id):
    user_post = Post.query.filter_by(id=post_id)
    if user_post:
        comments = Comment.query.filter_by(post_id=post_id).all()
        return render_template('post_viewer.html', post=user_post, comments=comments)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def comment(post_id):
    content = request.form['content']
    new_comment = Comment(content=content, post_id=post_id, user_id=current_user.id)
    db.session.add(new_comment)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/post/<int:post_id>/upvote', methods=['POST'])
@login_required
def upvote(post_id):
    new_upvote = Upvote(post_id=post_id, user_id=current_user.id)
    db.session.add(new_upvote)
    db.session.commit()
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    results = Post.query.filter(Post.name.ilike(f'%{query}%')).all()
    return render_template('search.html', results=results)


if __name__ == '__main__':
    app.run(debug=True)
