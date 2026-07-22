import os  # 운영체제의 환경변수를 읽기 위해 사용
from dotenv import load_dotenv  # .env 파일의 값을 환경변수로 불러옴
import sqlite3 # 별도의 서버 없이 파일 하나에 모든 데이터를 저장하는 가볍고 빠른 임베디드 SQL 데이터베이스
import uuid # 중복될 가능성이 매우 낮은 ID를 만듦
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
# 비밀번호 해시 적용
from werkzeug.security import generate_password_hash, check_password_hash
import re
# 요청 위조 방지를 위한 CSRF 보호 기능
from flask_wtf.csrf import CSRFProtect

# 프로젝트 루트의 .env 파일을 환경변수로 불러옴
load_dotenv()

app = Flask(__name__)

# 소스 코드가 아닌 실행 환경에서 세션 서명용 비밀키를 읽음
secret_key = os.getenv('SECRET_KEY')

# 비밀키가 없으면 안전하지 않은 상태로 실행하지 않고 즉시 중단
if not secret_key:
    raise RuntimeError('SECRET_KEY 환경변수가 설정되지 않았습니다.')

app.config['SECRET_KEY'] = secret_key

# POST 요청에 포함된 CSRF 토큰이 서버가 발급한 토큰과 일치하는지 검사
csrf = CSRFProtect(app)
# 서버 측 입력값 검증 기준
MAX_BIO_LENGTH = 500
MAX_PRODUCT_TITLE_LENGTH = 100
MAX_PRODUCT_DESCRIPTION_LENGTH = 2000
MAX_PRODUCT_PRICE = 1_000_000_000
MAX_REPORT_REASON_LENGTH = 1000

USERNAME_PATTERN = re.compile(r'[A-Za-z0-9_]{4,20}')
DATABASE = 'market.db'
socketio = SocketIO(app) # 현재 Flask app에 실시간 통신 기능을 붙임

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    #  g 안에 _database라는 값이 있으면 가져오고, 없으면 None을 반환
    db = getattr(g, '_database', None) # g: 현재 HTTP 요청 동안 잠깐 데이터를 저장하는 Flask 객체
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # DB 조회 결과를 번호뿐 아니라 열 이름으로도 사용할 수 있게 함 (user['id'], user['username']처럼)
    return db

# 애플리케이션 요청 처리가 끝나면 close_connection()을 자동으로 실행
@app.teardown_appcontext
def close_connection(exception): # 정상 종료: None, 오류 발생 후 종료: 오류 정보
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context(): # Flask 앱과 관련된 기능을 사용할 수 있는 임시 환경을 만듦
        db = get_db()
        cursor = db.cursor() # 연결에서 SQL문을 실행할 커서 객체를 만듦
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '') # 비밀번호에는 .strip()을 붙이지 않음. 앞뒤 공백도 사용자가 정한 실제 비밀번호의 일부일 수 있기 때문

        # 사용자명: 4~20자, 영문·숫자·밑줄만 허용
        if not USERNAME_PATTERN.fullmatch(username):
            flash('사용자명은 4~20자의 영문, 숫자, 밑줄(_)만 사용할 수 있습니다.')
            return render_template('register.html'), 400

        # 비밀번호: 8~64자
        if not 8 <= len(password) <= 64:
            flash('비밀번호는 8~64자로 입력해야 합니다.')
            return render_template('register.html'), 400

        db = get_db()
        cursor = db.cursor()

        # 중복 사용자 확인
        cursor.execute(
            "SELECT * FROM user WHERE username = ?",
            (username,)
        )

        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return render_template('register.html'), 400

        # 모든 검증을 통과한 뒤 비밀번호 해시 생성
        user_id = str(uuid.uuid4())
        password_hash = generate_password_hash(password)

        cursor.execute(
            "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
            (user_id, username, password_hash)
        )
        db.commit()

        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))

    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username, ))
        user = cursor.fetchone() # SQL 쿼리 실행 결과에서 단 하나의 행(Row)만을 가져올 때 사용
        if user and check_password_hash(user['password'], password): # 해시값 확인
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))  # 웹 서버가 클라이언트에게 요청한 페이지가 아닌 다른 URL로 재접속하도록 지시하는 기능
    return render_template('login.html')

# 세션 상태를 변경하므로 POST 요청과 CSRF 검증을 사용
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT * FROM user WHERE id = ?",
        (session['user_id'],)
    )
    current_user = cursor.fetchone()

    # 삭제된 사용자 등의 오래된 세션 처리
    if current_user is None:
        session.clear()
        flash('사용자 정보를 찾을 수 없습니다. 다시 로그인해주세요.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # 앞뒤 공백을 제거하고 서버에서 길이를 직접 검사
        bio = request.form.get('bio', '').strip()

        if len(bio) > MAX_BIO_LENGTH:
            flash(f'소개글은 {MAX_BIO_LENGTH}자 이하로 입력해주세요.')
            return render_template(
                'profile.html',
                user=current_user
            ), 400

        cursor.execute(
            "UPDATE user SET bio = ? WHERE id = ?",
            (bio, session['user_id'])
        )
        db.commit()

        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price_text = request.form.get('price', '').strip()

        if not title:
            flash('상품 제목을 입력해주세요.')
            return render_template('new_product.html'), 400

        if len(title) > MAX_PRODUCT_TITLE_LENGTH:
            flash(f'상품 제목은 {MAX_PRODUCT_TITLE_LENGTH}자 이하로 입력해주세요.')
            return render_template('new_product.html'), 400

        if not description:
            flash('상품 설명을 입력해주세요.')
            return render_template('new_product.html'), 400

        if len(description) > MAX_PRODUCT_DESCRIPTION_LENGTH:
            flash(
                f'상품 설명은 {MAX_PRODUCT_DESCRIPTION_LENGTH}자 이하로 입력해주세요.'
            )
            return render_template('new_product.html'), 400

        # 숫자 이외의 문자와 지나치게 긴 숫자를 거부
        if not re.fullmatch(r'[0-9]{1,10}', price_text):
            flash('가격은 숫자로만 입력해주세요.')
            return render_template('new_product.html'), 400

        price = int(price_text)

        if not 1 <= price <= MAX_PRODUCT_PRICE:
            flash(
                f'가격은 1원 이상 {MAX_PRODUCT_PRICE:,}원 이하로 입력해주세요.'
            )
            return render_template('new_product.html'), 400

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())

        cursor.execute(
            """
            INSERT INTO product
                (id, title, description, price, seller_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                product_id,
                title,
                description,
                price,
                session['user_id']
            )
        )
        db.commit()

        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        target_id = request.form.get('target_id', '').strip()
        reason = request.form.get('reason', '').strip()

        if not target_id:
            flash('신고 대상을 입력해주세요.')
            return render_template('report.html'), 400

        # UUID 형식을 검사하고 표준 형식으로 변환
        try:
            target_id = str(uuid.UUID(target_id))
        except ValueError:
            flash('신고 대상 ID 형식이 올바르지 않습니다.')
            return render_template('report.html'), 400

        if not reason:
            flash('신고 사유를 입력해주세요.')
            return render_template('report.html'), 400

        if len(reason) > MAX_REPORT_REASON_LENGTH:
            flash(
                f'신고 사유는 {MAX_REPORT_REASON_LENGTH}자 이하로 입력해주세요.'
            )
            return render_template('report.html'), 400

        db = get_db()
        cursor = db.cursor()

        # 사용자 또는 상품 중 실제로 존재하는 대상인지 확인
        cursor.execute(
            "SELECT 1 FROM user WHERE id = ?",
            (target_id,)
        )
        target_exists = cursor.fetchone() is not None

        if not target_exists:
            cursor.execute(
                "SELECT 1 FROM product WHERE id = ?",
                (target_id,)
            )
            target_exists = cursor.fetchone() is not None

        if not target_exists:
            flash('존재하지 않는 신고 대상입니다.')
            return render_template('report.html'), 400

        report_id = str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO report (id, reporter_id, target_id, reason)
            VALUES (?, ?, ?, ?)
            """,
            (
                report_id,
                session['user_id'],
                target_id,
                reason
            )
        )
        db.commit()

        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data): # data: 클라이언트가 보낸 채팅 데이터
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    # 상세 오류 화면과 디버거가 외부에 노출되지 않도록 비활성화
    socketio.run(app, debug=False)
