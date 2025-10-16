from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///teamtasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='developer')

    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    title = db.Column(db.String(300), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        un = request.form['username'].strip()
        pwd = request.form['password']
        role = request.form.get('role', 'developer')
        if User.query.filter_by(username=un).first():
            flash('Username taken', 'danger')
            return redirect(url_for('register'))
        u = User(username=un, role=role)
        u.set_password(pwd)
        db.session.add(u)
        db.session.commit()
        flash('Registered. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        un = request.form['username'].strip()
        pwd = request.form['password']
        u = User.query.filter_by(username=un).first()
        if u and u.check_password(pwd):
            login_user(u)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST' and current_user.role == 'manager':
        group_name = request.form.get('group_name')
        if group_name:
            g = Group(name=group_name, created_by=current_user.id)
            db.session.add(g)
            db.session.commit()
            flash('Group created', 'success')
            gm = GroupMember(group_id=g.id, user_id=current_user.id)
            db.session.add(gm)
            db.session.commit()
        return redirect(url_for('dashboard'))

    memberships = GroupMember.query.filter_by(user_id=current_user.id).all()
    member_group_ids = [m.group_id for m in memberships]
    groups = Group.query.filter((Group.id.in_(member_group_ids)) | (Group.created_by==current_user.id)).all()
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('dashboard.html', groups=groups, users=users, member_group_ids=member_group_ids)


@app.route('/group/<int:group_id>/add_user', methods=['POST'])
@login_required
def add_user(group_id):
    if current_user.role != 'manager':
        flash('Only managers can add users.', 'danger')
        return redirect(url_for('dashboard'))

    user_id = request.form.get('user_id')
    if not user_id:
        flash('No user selected', 'danger')
        return redirect(url_for('dashboard'))

    group = Group.query.get(group_id)
    if not group:
        flash('Group not found', 'danger')
        return redirect(url_for('dashboard'))

    if GroupMember.query.filter_by(group_id=group_id, user_id=int(user_id)).first():
        flash('User already in group', 'warning')
        return redirect(url_for('dashboard'))

    gm = GroupMember(group_id=group_id, user_id=int(user_id))
    db.session.add(gm)
    db.session.commit()
    flash('User added to group', 'success')
    return redirect(url_for('dashboard'))


@app.route('/group/join', methods=['POST'])
@login_required
def join_group():
    data = request.get_json()
    if not data or 'group_id' not in data:
        return jsonify({'ok': False, 'msg': 'Group ID missing'}), 400

    group_id = data['group_id']
    group = Group.query.get(group_id)
    if not group:
        return jsonify({'ok': False, 'msg': 'Group not found'}), 404

    if GroupMember.query.filter_by(group_id=group.id, user_id=current_user.id).first():
        return jsonify({'ok': False, 'msg': 'Already a member'}), 400

    gm = GroupMember(group_id=group.id, user_id=current_user.id)
    db.session.add(gm)
    db.session.commit()

    socketio.emit('member_joined', {
        'user_id': current_user.id,
        'username': current_user.username,
        'group_id': group.id
    }, room=f'group_{group.id}')

    return jsonify({'ok': True, 'msg': 'Joined group successfully'})


@app.route('/group/<int:group_id>')
@login_required
def group_page(group_id):
    group = Group.query.get_or_404(group_id)
    members = db.session.query(User).join(GroupMember, User.id==GroupMember.user_id)\
        .filter(GroupMember.group_id==group_id).all()
    tasks = Task.query.filter_by(group_id=group_id).order_by(Task.created_at.desc()).all()
    messages = Message.query.filter_by(group_id=group_id).order_by(Message.timestamp.asc()).all()
    current_user_in_group = GroupMember.query.filter_by(group_id=group.id, user_id=current_user.id).first() is not None
    return render_template(
        'group.html',
        group=group,
        members=members,
        tasks=tasks,
        messages=messages,
        current_user=current_user,
        current_user_in_group=current_user_in_group
    )


@app.route('/task/create', methods=['POST'])
@login_required
def create_task():
    title = request.form.get('title')
    group_id = request.form.get('group_id')
    assigned_to = request.form.get('assigned_to') or None
    if not title or not group_id:
        return jsonify({'ok': False, 'msg': 'Missing fields'}), 400
    t = Task(title=title, group_id=int(group_id), assigned_to=int(assigned_to) if assigned_to else None)
    db.session.add(t)
    db.session.commit()
    socketio.emit('task_created', {
        'id': t.id, 'title': t.title, 'assigned_to': t.assigned_to, 'completed': t.completed, 'group_id': t.group_id
    }, room=f'group_{group_id}')
    return jsonify({'ok': True, 'task_id': t.id})


@app.route('/task/toggle', methods=['POST'])
@login_required
def toggle_task():
    task_id = request.form.get('task_id')
    t = Task.query.get(task_id)
    if not t:
        return jsonify({'ok': False, 'msg': 'Task not found'}), 404
    t.completed = not t.completed
    db.session.commit()
    socketio.emit('task_toggled', {'id': t.id, 'completed': t.completed, 'group_id': t.group_id}, room=f'group_{t.group_id}')
    return jsonify({'ok': True, 'completed': t.completed})



@socketio.on('join')
def handle_join(data):
    join_room(f'group_{data["group_id"]}')
    emit('status', {'msg': f'{data["username"]} has joined.'}, room=f'group_{data["group_id"]}')


@socketio.on('leave')
def handle_leave(data):
    leave_room(f'group_{data["group_id"]}')
    emit('status', {'msg': f'{data["username"]} has left.'}, room=f'group_{data["group_id"]}')


@socketio.on('send_message')
def handle_send_message(data):
    msg = Message(group_id=data['group_id'], sender_id=data['user_id'], content=data['content'])
    db.session.add(msg)
    db.session.commit()
    emit('receive_message', {'sender': data['username'], 'content': data['content'], 'timestamp': datetime.utcnow().isoformat()}, room=f'group_{data["group_id"]}')



def create_demo_users():
    if not User.query.filter_by(username='manager').first():
        m = User(username='manager', role='manager'); m.set_password('manager'); db.session.add(m)
    if not User.query.filter_by(username='dev1').first():
        d = User(username='dev1', role='developer'); d.set_password('dev1'); db.session.add(d)
    if not User.query.filter_by(username='dev2').first():
        d2 = User(username='dev2', role='developer'); d2.set_password('dev2'); db.session.add(d2)
    db.session.commit()


if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('teamtasks.db'):
            db.create_all()
            create_demo_users()
            print('DB created and demo users added: manager/manager, dev1/dev1, dev2/dev2')
    socketio.run(app, debug=True)
