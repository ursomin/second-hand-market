import os
import re
import sqlite3
import uuid
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_socketio import SocketIO, disconnect, send
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


# 프로젝트 루트의 .env 파일에 저장된 환경변수를 불러온다.
load_dotenv()

app = Flask(__name__)

# 세션 쿠키를 위조하지 못하도록 서명할 때 사용하는 비밀키이다.
# 소스 코드에 직접 적지 않고 .env의 SECRET_KEY에서만 가져온다.
secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY 환경변수가 설정되지 않았습니다.")

app.config.update(
    SECRET_KEY=secret_key,
    # JavaScript에서 세션 쿠키를 읽지 못하게 하여 쿠키 탈취 위험을 줄인다.
    SESSION_COOKIE_HTTPONLY=True,
    # 다른 사이트에서 시작된 일반적인 CSRF 요청에 쿠키가 전송되는 것을 줄인다.
    SESSION_COOKIE_SAMESITE="Lax",
    # 로컬 HTTP에서는 False로 두고, HTTPS 배포 환경의 .env에서 true로 설정한다.
    SESSION_COOKIE_SECURE=(
        os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    ),
)

# POST 폼 등 상태를 변경하는 HTTP 요청에 CSRF 토큰 검사를 적용한다.
csrf = CSRFProtect(app)

# 현재 Flask 애플리케이션에 실시간 Socket.IO 통신 기능을 연결한다.
socketio = SocketIO(app)


# ---------------------------------------------------------------------------
# 입력값 및 상태 상수
# ---------------------------------------------------------------------------

# 서버에서도 길이와 범위를 검사해야 HTML 속성을 우회한 요청을 막을 수 있다.
MAX_BIO_LENGTH = 500
MAX_PRODUCT_TITLE_LENGTH = 100
MAX_PRODUCT_DESCRIPTION_LENGTH = 2_000
MAX_PRODUCT_PRICE = 100_000_000
MAX_REPORT_REASON_LENGTH = 1_000
MAX_CHAT_MESSAGE_LENGTH = 500
MAX_SEARCH_QUERY_LENGTH = 100

USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_]{4,20}")
USER_STATUSES = {"active", "restricted"}
PRODUCT_MODERATION_STATUSES = {"visible", "blocked"}

# 실행 위치가 달라도 항상 app.py와 같은 폴더의 market.db를 사용한다.
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.getenv("DATABASE_PATH", os.path.join(BASE_DIR, "market.db"))


# ---------------------------------------------------------------------------
# 데이터베이스 연결 및 초기화
# ---------------------------------------------------------------------------

def get_db():
    """현재 요청에서 사용할 SQLite 연결을 하나만 만들어 반환한다."""
    db = getattr(g, "_database", None)

    if db is None:
        db = g._database = sqlite3.connect(DATABASE)

        # 조회 결과를 user["id"]처럼 열 이름으로 읽을 수 있게 한다.
        db.row_factory = sqlite3.Row

        # SQLite는 외래키 검사가 기본적으로 꺼져 있으므로 연결마다 활성화한다.
        db.execute("PRAGMA foreign_keys = ON")

    return db


@app.teardown_appcontext
def close_connection(exception):
    """HTTP 또는 Socket.IO 요청 처리가 끝나면 DB 연결을 닫는다."""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def _get_column_names(cursor, table_name):
    """마이그레이션을 위해 특정 테이블의 현재 열 이름을 조회한다."""
    # table_name은 아래 init_db()에서 정한 고정 문자열만 전달한다.
    rows = cursor.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def init_db():
    """필요한 테이블을 만들고 기존 실습 DB에 새 열을 추가한다."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 사용자 테이블: role은 권한, status는 서비스 이용 가능 상태를 뜻한다.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                role TEXT NOT NULL DEFAULT 'user'
                    CHECK (role IN ('user', 'admin')),
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'restricted'))
            )
            """
        )

        # moderation_status가 blocked인 상품은 일반 목록과 상세 화면에서 숨긴다.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                moderation_status TEXT NOT NULL DEFAULT 'visible'
                    CHECK (moderation_status IN ('visible', 'blocked')),
                FOREIGN KEY (seller_id) REFERENCES user (id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                FOREIGN KEY (reporter_id) REFERENCES user (id)
            )
            """
        )

        # CREATE TABLE IF NOT EXISTS는 이미 존재하는 테이블의 구조를 바꾸지 않는다.
        # 따라서 예전 market.db를 계속 사용할 수 있도록 필요한 열만 직접 추가한다.
        user_columns = _get_column_names(cursor, "user")

        if "role" not in user_columns:
            cursor.execute(
                "ALTER TABLE user "
                "ADD COLUMN role TEXT NOT NULL DEFAULT 'user'"
            )

        if "status" not in user_columns:
            cursor.execute(
                "ALTER TABLE user "
                "ADD COLUMN status TEXT NOT NULL DEFAULT 'active'"
            )

        product_columns = _get_column_names(cursor, "product")

        if "moderation_status" not in product_columns:
            cursor.execute(
                "ALTER TABLE product "
                "ADD COLUMN moderation_status TEXT NOT NULL DEFAULT 'visible'"
            )

        db.commit()


# ---------------------------------------------------------------------------
# 현재 사용자 조회 및 접근 권한 검사
# ---------------------------------------------------------------------------

def get_current_user():
    """세션의 user_id로 현재 사용자를 DB에서 조회한다."""
    # 같은 요청 안에서 여러 번 호출되어도 DB 조회는 한 번만 수행한다.
    if "current_user" not in g:
        user_id = session.get("user_id")

        if user_id is None:
            g.current_user = None
        else:
            g.current_user = get_db().execute(
                "SELECT * FROM user WHERE id = ?",
                (user_id,),
            ).fetchone()

    return g.current_user


def login_required(view_function):
    """로그인한 사용자만 라우트에 접근하게 하는 데코레이터이다."""
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if get_current_user() is None:
            # 삭제된 계정의 오래된 세션도 함께 제거한다.
            session.clear()
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))

        return view_function(*args, **kwargs)

    return wrapped_view


def active_user_required(view_function):
    """로그인했고 이용 상태가 active인 사용자만 기능을 실행하게 한다."""
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        current_user = get_current_user()

        if current_user is None:
            session.clear()
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))

        if current_user["status"] != "active":
            flash("이용 제한된 계정에서는 해당 기능을 사용할 수 없습니다.")
            return redirect(url_for("dashboard"))

        return view_function(*args, **kwargs)

    return wrapped_view


def admin_required(view_function):
    """DB에서 확인한 활성 관리자만 관리자 기능을 실행하게 한다."""
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        current_user = get_current_user()

        if current_user is None:
            session.clear()
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))

        # 화면에 표시된 session['role']은 메뉴 표시용일 뿐이다.
        # 실제 권한은 요청마다 DB의 role과 status를 다시 확인한다.
        if (
            current_user["role"] != "admin"
            or current_user["status"] != "active"
        ):
            flash("관리자 권한이 필요합니다.")
            return redirect(url_for("dashboard"))

        return view_function(*args, **kwargs)

    return wrapped_view


# ---------------------------------------------------------------------------
# 기본 화면, 회원가입, 로그인, 로그아웃
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """입력값을 검증하고 비밀번호를 해시한 뒤 새 사용자를 등록한다."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()

        # 비밀번호 앞뒤 공백도 사용자가 정한 값의 일부일 수 있으므로 strip하지 않는다.
        password = request.form.get("password", "")

        if not USERNAME_PATTERN.fullmatch(username):
            flash("사용자명은 4~20자의 영문, 숫자, 밑줄(_)만 사용할 수 있습니다.")
            return render_template("register.html"), 400

        if not 8 <= len(password) <= 64:
            flash("비밀번호는 8~64자로 입력해야 합니다.")
            return render_template("register.html"), 400

        db = get_db()

        # COLLATE NOCASE를 사용하여 Gyumin과 gyumin 같은 계정의 중복도 막는다.
        existing_user = db.execute(
            "SELECT id FROM user WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()

        if existing_user is not None:
            flash("이미 존재하는 사용자명입니다.")
            return render_template("register.html"), 400

        user_id = str(uuid.uuid4())
        password_hash = generate_password_hash(password)

        try:
            db.execute(
                "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                (user_id, username, password_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            # 중복 확인 직후 동시에 같은 계정이 생성되는 경쟁 상황도 안전하게 처리한다.
            db.rollback()
            flash("이미 존재하는 사용자명입니다.")
            return render_template("register.html"), 400

        flash("회원가입이 완료되었습니다. 로그인해주세요.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """저장된 비밀번호 해시를 확인하고 로그인 세션을 발급한다."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM user WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            # 로그인 전 세션값을 제거하여 기존 세션을 그대로 사용하는 위험을 줄인다.
            session.clear()
            session["user_id"] = user["id"]

            # role은 관리자 메뉴 표시용이다. 실제 권한 검사는 admin_required가 한다.
            session["role"] = user["role"]

            flash("로그인 성공!")
            return redirect(url_for("dashboard"))

        # 계정 존재 여부가 노출되지 않도록 두 실패 원인에 같은 문구를 사용한다.
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    """세션을 변경하는 로그아웃은 GET이 아닌 POST와 CSRF 검증으로 처리한다."""
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# 상품 목록·검색 및 프로필
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    """차단되지 않은 상품을 표시하고 상품명·설명 검색을 처리한다."""
    current_user = get_current_user()

    # DB에서 읽은 최신 role을 세션에 동기화한다. 이 값은 메뉴 표시용이다.
    session["role"] = current_user["role"]

    query = request.args.get("q", "").strip()

    if len(query) > MAX_SEARCH_QUERY_LENGTH:
        flash(f"검색어는 {MAX_SEARCH_QUERY_LENGTH}자 이하로 입력해주세요.")
        return render_template(
            "dashboard.html",
            products=[],
            user=current_user,
            query=query,
        ), 400

    db = get_db()

    if query:
        # LIKE에서 특수한 의미를 갖는 !, %, _를 일반 문자로 검색하게 만든다.
        escaped_query = (
            query.replace("!", "!!")
            .replace("%", "!%")
            .replace("_", "!_")
        )
        search_pattern = f"%{escaped_query}%"

        # 상품 상태와 판매자 상태를 함께 검사해야 제한된 사용자의 상품도 숨겨진다.
        products = db.execute(
            """
            SELECT p.*
            FROM product AS p
            JOIN user AS seller ON seller.id = p.seller_id
            WHERE p.moderation_status = 'visible'
              AND seller.status = 'active'
              AND (
                  p.title LIKE ? ESCAPE '!'
                  OR p.description LIKE ? ESCAPE '!'
              )
            ORDER BY p.title COLLATE NOCASE
            """,
            (search_pattern, search_pattern),
        ).fetchall()
    else:
        products = db.execute(
            """
            SELECT p.*
            FROM product AS p
            JOIN user AS seller ON seller.id = p.seller_id
            WHERE p.moderation_status = 'visible'
              AND seller.status = 'active'
            ORDER BY p.title COLLATE NOCASE
            """
        ).fetchall()

    return render_template(
        "dashboard.html",
        products=products,
        user=current_user,
        query=query,
    )


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """현재 로그인한 사용자의 소개글만 조회하고 수정한다."""
    current_user = get_current_user()

    if request.method == "POST":
        bio = request.form.get("bio", "").strip()

        if len(bio) > MAX_BIO_LENGTH:
            flash(f"소개글은 {MAX_BIO_LENGTH}자 이하로 입력해주세요.")
            return render_template("profile.html", user=current_user), 400

        db = get_db()
        db.execute(
            "UPDATE user SET bio = ? WHERE id = ?",
            (bio, current_user["id"]),
        )
        db.commit()

        flash("프로필이 업데이트되었습니다.")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=current_user)


# ---------------------------------------------------------------------------
# 상품 등록 및 상세 조회
# ---------------------------------------------------------------------------

@app.route("/product/new", methods=["GET", "POST"])
@active_user_required
def new_product():
    """정상 상태의 회원만 검증된 상품 정보를 등록하게 한다."""
    current_user = get_current_user()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        price_text = request.form.get("price", "").strip()

        if not title:
            flash("상품 제목을 입력해주세요.")
            return render_template("new_product.html"), 400

        if len(title) > MAX_PRODUCT_TITLE_LENGTH:
            flash(f"상품 제목은 {MAX_PRODUCT_TITLE_LENGTH}자 이하로 입력해주세요.")
            return render_template("new_product.html"), 400

        if not description:
            flash("상품 설명을 입력해주세요.")
            return render_template("new_product.html"), 400

        if len(description) > MAX_PRODUCT_DESCRIPTION_LENGTH:
            flash(
                f"상품 설명은 {MAX_PRODUCT_DESCRIPTION_LENGTH}자 이하로 입력해주세요."
            )
            return render_template("new_product.html"), 400

        # int()만 호출하기 전에 숫자 형식과 최대 자릿수를 먼저 제한한다.
        if not re.fullmatch(r"[0-9]{1,10}", price_text):
            flash("가격은 숫자로만 입력해주세요.")
            return render_template("new_product.html"), 400

        price = int(price_text)

        if not 1 <= price <= MAX_PRODUCT_PRICE:
            flash(f"가격은 1원 이상 {MAX_PRODUCT_PRICE:,}원 이하로 입력해주세요.")
            return render_template("new_product.html"), 400

        db = get_db()
        db.execute(
            """
            INSERT INTO product (id, title, description, price, seller_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                title,
                description,
                price,
                current_user["id"],
            ),
        )
        db.commit()

        flash("상품이 등록되었습니다.")
        return redirect(url_for("dashboard"))

    return render_template("new_product.html")


@app.route("/product/<product_id>")
def view_product(product_id):
    """차단 상품과 제한된 판매자의 상품은 직접 URL로도 조회하지 못하게 한다."""
    db = get_db()

    product = db.execute(
        """
        SELECT p.*
        FROM product AS p
        JOIN user AS seller ON seller.id = p.seller_id
        WHERE p.id = ?
          AND p.moderation_status = 'visible'
          AND seller.status = 'active'
        """,
        (product_id,),
    ).fetchone()

    if product is None:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for("dashboard"))

    seller = db.execute(
        "SELECT * FROM user WHERE id = ?",
        (product["seller_id"],),
    ).fetchone()

    return render_template(
        "view_product.html",
        product=product,
        seller=seller,
    )


# ---------------------------------------------------------------------------
# 신고 접수
# ---------------------------------------------------------------------------

@app.route("/report", methods=["GET", "POST"])
@active_user_required
def report():
    """정상 사용자가 실제로 존재하는 사용자 또는 상품을 신고하게 한다."""
    current_user = get_current_user()

    if request.method == "POST":
        target_id = request.form.get("target_id", "").strip()
        reason = request.form.get("reason", "").strip()

        if not target_id:
            flash("신고 대상을 입력해주세요.")
            return render_template("report.html"), 400

        # UUID 형식을 검사한 뒤 같은 값을 항상 표준 문자열 형태로 저장한다.
        try:
            target_id = str(uuid.UUID(target_id))
        except ValueError:
            flash("신고 대상 ID 형식이 올바르지 않습니다.")
            return render_template("report.html"), 400

        if len(reason) < 10:
            flash("신고 사유는 10자 이상 입력해주세요.")
            return render_template("report.html"), 400

        if len(reason) > MAX_REPORT_REASON_LENGTH:
            flash(f"신고 사유는 {MAX_REPORT_REASON_LENGTH}자 이하로 입력해주세요.")
            return render_template("report.html"), 400

        db = get_db()

        # 사용자와 상품 어느 쪽에도 없는 임의의 UUID는 신고 대상으로 받지 않는다.
        target_exists = db.execute(
            "SELECT 1 FROM user WHERE id = ?",
            (target_id,),
        ).fetchone() is not None

        if not target_exists:
            target_exists = db.execute(
                "SELECT 1 FROM product WHERE id = ?",
                (target_id,),
            ).fetchone() is not None

        if not target_exists:
            flash("존재하지 않는 신고 대상입니다.")
            return render_template("report.html"), 400

        db.execute(
            """
            INSERT INTO report (id, reporter_id, target_id, reason)
            VALUES (?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                current_user["id"],
                target_id,
                reason,
            ),
        )
        db.commit()

        flash("신고가 접수되었습니다.")
        return redirect(url_for("dashboard"))

    return render_template("report.html")


# ---------------------------------------------------------------------------
# 관리자: 사용자 및 상품 상태 관리
# ---------------------------------------------------------------------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    """관리자가 전체 사용자와 전체 상품의 현재 상태를 조회한다."""
    db = get_db()

    users = db.execute(
        """
        SELECT id, username, role, status
        FROM user
        ORDER BY username COLLATE NOCASE
        """
    ).fetchall()

    # 차단된 상품도 관리자는 확인하고 해제할 수 있어야 하므로 모두 조회한다.
    products = db.execute(
        """
        SELECT
            p.id,
            p.title,
            p.price,
            p.moderation_status,
            u.username AS seller_username
        FROM product AS p
        JOIN user AS u ON u.id = p.seller_id
        ORDER BY p.title COLLATE NOCASE
        """
    ).fetchall()

    return render_template(
        "admin.html",
        users=users,
        products=products,
    )


@app.route("/admin/users/<user_id>/status", methods=["POST"])
@admin_required
def admin_update_user_status(user_id):
    """관리자가 일반 사용자를 이용 제한하거나 다시 활성화한다."""
    new_status = request.form.get("status", "").strip()

    # 클라이언트가 임의 상태 문자열을 보내도 허용 목록 외에는 저장하지 않는다.
    if new_status not in USER_STATUSES:
        flash("올바르지 않은 사용자 상태입니다.")
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    target_user = db.execute(
        "SELECT id, username, role FROM user WHERE id = ?",
        (user_id,),
    ).fetchone()

    if target_user is None:
        flash("사용자를 찾을 수 없습니다.")
        return redirect(url_for("admin_dashboard"))

    # 관리자 계정을 제한해 관리 권한을 잃는 사고나 관리자 간 방해를 막는다.
    if target_user["role"] == "admin":
        flash("관리자 계정의 상태는 이 화면에서 변경할 수 없습니다.")
        return redirect(url_for("admin_dashboard"))

    db.execute(
        "UPDATE user SET status = ? WHERE id = ?",
        (new_status, user_id),
    )
    db.commit()

    flash(f"{target_user['username']} 계정 상태를 변경했습니다.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/products/<product_id>/moderation", methods=["POST"])
@admin_required
def admin_update_product_moderation(product_id):
    """관리자가 상품을 일반 화면에서 차단하거나 다시 공개한다."""
    new_status = request.form.get("moderation_status", "").strip()

    if new_status not in PRODUCT_MODERATION_STATUSES:
        flash("올바르지 않은 상품 상태입니다.")
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    product = db.execute(
        "SELECT id, title FROM product WHERE id = ?",
        (product_id,),
    ).fetchone()

    if product is None:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for("admin_dashboard"))

    db.execute(
        "UPDATE product SET moderation_status = ? WHERE id = ?",
        (new_status, product_id),
    )
    db.commit()

    flash(f"{product['title']} 상품 상태를 변경했습니다.")
    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------------------------
# 실시간 전체 채팅
# ---------------------------------------------------------------------------

@socketio.on("connect")
def handle_socket_connect(auth=None):
    """비로그인 사용자와 이용 제한 사용자의 채팅 연결을 거부한다."""
    current_user = get_current_user()

    if current_user is None or current_user["status"] != "active":
        return False

    return None


@socketio.on("send_message")
def handle_send_message_event(data):
    """서버가 실제 발신자를 결정한 뒤 검증된 메시지만 전체 전송한다."""
    current_user = get_current_user()

    # 연결 뒤에 관리자가 계정을 제한할 수도 있으므로 전송할 때도 다시 검사한다.
    if current_user is None or current_user["status"] != "active":
        disconnect()
        return

    if not isinstance(data, dict):
        return

    message = data.get("message", "")

    if not isinstance(message, str):
        return

    message = message.strip()

    if not message or len(message) > MAX_CHAT_MESSAGE_LENGTH:
        return

    # 클라이언트가 보낸 username은 사용하지 않는다.
    # DB에서 확인한 로그인 사용자명만 발신자명으로 전달하여 사칭을 막는다.
    send(
        {
            "message_id": str(uuid.uuid4()),
            "username": current_user["username"],
            "message": message,
        },
        broadcast=True,
    )


if __name__ == "__main__":
    # 기존 DB 마이그레이션까지 완료한 뒤 서버를 시작한다.
    init_db()

    # 상세 오류 화면과 웹 디버거가 외부에 노출되지 않도록 끈다.
    socketio.run(app, debug=False)