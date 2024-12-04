from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stores.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 使用者模型
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 店舖模型
class Store(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    product = db.Column(db.String(100), nullable=False)

# 評價模型
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 評分（1-5 分）
    store_id = db.Column(db.Integer, db.ForeignKey('store.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    store = db.relationship('Store', backref=db.backref('reviews', lazy=True))
    user = db.relationship('User', backref=db.backref('reviews', lazy=True))

# 初始化資料庫表並插入範例店舖
def init_db():
    db.create_all()
    if not Store.query.first():
        sample_stores = [
            Store(name="書店 A", address="台北市信義區", product="書籍"),
            Store(name="咖啡店 B", address="新北市板橋區", product="咖啡"),
            Store(name="服飾店 C", address="台中市西屯區", product="服飾")
        ]
        db.session.bulk_save_objects(sample_stores)
        db.session.commit()

with app.app_context():
    init_db()

# 加載使用者
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    stores = Store.query.all()
    return render_template('index.html', stores=stores)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_store():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        product = request.form['product']
        
        new_store = Store(name=name, address=address, product=product)
        db.session.add(new_store)
        db.session.commit()
        
        return redirect(url_for('index'))
    return render_template('add_store.html')

@app.route('/store/<int:store_id>', methods=['GET', 'POST'])
@login_required
def store_detail(store_id):
    store = Store.query.get_or_404(store_id)
    if request.method == 'POST':
        content = request.form['content']
        rating = int(request.form['rating'])
        
        new_review = Review(content=content, rating=rating, store_id=store_id, user_id=current_user.id)
        db.session.add(new_review)
        db.session.commit()
        
        return redirect(url_for('store_detail', store_id=store_id))
    
    reviews = Review.query.filter_by(store_id=store_id).all()
    return render_template('store_detail.html', store=store, reviews=reviews)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('使用者名稱已存在')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('註冊成功，請登入')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('登入失敗，請檢查使用者名稱和密碼')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('您已成功登出')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
