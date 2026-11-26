from datetime import datetime
from functools import wraps
import json
import os
import secrets

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "database.json")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def init_db():
    if not os.path.exists(DB_PATH):
        with open(DB_PATH, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False, indent=4)


def load_users():
    init_db()
    with open(DB_PATH, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []


def save_users(users):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=4)


def get_next_id(users):
    if not users:
        return 1
    return max(u.get("id", 0) for u in users) + 1


def find_user_by_id(user_id):
    users = load_users()
    for u in users:
        if u.get("id") == user_id:
            return u
    return None


def find_user_by_email(email):
    users = load_users()
    email_norm = (email or "").strip().lower()
    for u in users:
        if (u.get("email") or "").strip().lower() == email_norm:
            return u
    return None


def safe_user_dict(user):
    if not user:
        return None
    return {k: v for k, v in user.items() if k != "senha_hash"}


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            resp = make_response(render_template("erro_401.html"), 401)
            return resp
        user = find_user_by_id(user_id)
        if not user or user.get("excluido") is True:
            session.clear()
            resp = make_response(render_template("erro_401.html"), 401)
            return resp
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            resp = make_response(render_template("erro_401.html"), 401)
            return resp
        user = find_user_by_id(user_id)
        if not user or user.get("excluido") is True:
            session.clear()
            resp = make_response(render_template("erro_401.html"), 401)
            return resp
        if session.get("funcao") != "admin" or user.get("funcao") != "admin":
            resp = make_response(render_template("erro_403.html"), 403)
            return resp
        return f(*args, **kwargs)

    return decorated


def calcular_imc_dados(peso, altura, idade=25, sexo="masculino"):
    imc = peso / (altura ** 2)
    if imc < 18.5:
        classificacao = "Magreza"
        cor = "info"
        posicao_pct = min(max((imc / 18.5) * 20, 2), 24)
        recomendacao = "Aumente gradualmente a ingestão calórica com alimentos nutritivos e consulte um profissional de saúde."
    elif imc < 25:
        classificacao = "Normal"
        cor = "success"
        posicao_pct = 25 + ((imc - 18.5) / (25 - 18.5)) * 24
        recomendacao = "Mantenha a prática regular de exercícios físicos, boa hidratação e alimentação equilibrada."
    elif imc < 30:
        classificacao = "Sobrepeso"
        cor = "warning"
        posicao_pct = 50 + ((imc - 25) / (30 - 25)) * 24
        recomendacao = "Adote rotina de exercícios aeróbicos e de força combinada a ajustes alimentares."
    else:
        classificacao = "Obesidade"
        cor = "danger"
        posicao_pct = 75 + min(((imc - 30) / 15) * 23, 23)
        recomendacao = "Procure acompanhamento médico e nutricional para um plano seguro e sustentável de saúde."

    peso_min = 18.5 * (altura ** 2)
    peso_max = 24.9 * (altura ** 2)

    sexo_norm = (sexo or "masculino").strip().lower()
    sex_val = 1 if sexo_norm in ("m", "masc", "masculino", "homem") else 0
    gordura_est = (1.20 * imc) + (0.23 * idade) - (10.8 * sex_val) - 5.4
    gordura_est = max(gordura_est, 2.0)

    if sex_val == 1:
        if gordura_est < 6:
            gordura_cat = "Essencial"
        elif gordura_est < 14:
            gordura_cat = "Atlético"
        elif gordura_est < 18:
            gordura_cat = "Fitness"
        elif gordura_est < 25:
            gordura_cat = "Aceitável"
        else:
            gordura_cat = "Obesidade"
    else:
        if gordura_est < 14:
            gordura_cat = "Essencial"
        elif gordura_est < 21:
            gordura_cat = "Atlético"
        elif gordura_est < 25:
            gordura_cat = "Fitness"
        elif gordura_est < 32:
            gordura_cat = "Aceitável"
        else:
            gordura_cat = "Obesidade"

    return {
        "peso": round(peso, 2),
        "altura": round(altura, 2),
        "idade": idade,
        "sexo": "Masculino" if sex_val == 1 else "Feminino",
        "imc": round(imc, 2),
        "classificacao": classificacao,
        "cor": cor,
        "posicao_pct": round(posicao_pct, 1),
        "peso_ideal_min": round(peso_min, 1),
        "peso_ideal_max": round(peso_max, 1),
        "gordura_corporal": round(gordura_est, 1),
        "gordura_classificacao": gordura_cat,
        "recomendacao": recomendacao,
    }


@app.context_processor
def inject_user():
    current_user = None
    if session.get("user_id"):
        u = find_user_by_id(session.get("user_id"))
        if u and u.get("excluido") is not True:
            current_user = safe_user_dict(u)
    return {"current_user": current_user}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    equipe = [
        {"nome": "Maykol Silva", "iniciais": "MS", "foto": None, "papel": "Desenvolvimento & Saúde"},
        {"nome": "Integrante 2", "iniciais": "I2", "foto": None, "papel": "Front-end & UI"},
    ]
    recursos = [
        {"icone": "⚖️", "titulo": "Calculadora de IMC", "descricao": "Cálculo rápido do IMC, peso ideal e percentual de gordura corporal estimado."},
        {"icone": "🧮", "titulo": "Operações Matemáticas", "descricao": "Realize operações básicas com exibição clara da expressão e resultado."},
        {"icone": "🔐", "titulo": "Gestão de Conta", "descricao": "Cadastro, autenticação segura e perfil personalizado com suas metas."},
    ]
    return render_template("about.html", equipe=equipe, recursos=recursos)


@app.route("/login", methods=["GET", "POST"])
def login():
    email_preenchido = ""
    if request.method == "POST":
        email = (request.form.get("email") or request.form.get("usuario") or "").strip()
        senha = request.form.get("senha") or ""
        email_preenchido = email

        if not email or not senha:
            flash("Preencha o e-mail e a senha.", "error")
            return render_template("login.html", email=email_preenchido)

        user = find_user_by_email(email)
        if not user or user.get("excluido") is True:
            flash("E-mail ou senha inválidos, ou conta inativa.", "error")
            return render_template("login.html", email=email_preenchido)

        if not check_password_hash(user.get("senha_hash", ""), senha):
            flash("E-mail ou senha inválidos.", "error")
            return render_template("login.html", email=email_preenchido)

        session.clear()
        session["user_id"] = user["id"]
        session["email"] = user["email"]
        session["funcao"] = user.get("funcao", "comum")
        flash("Login realizado com sucesso!", "success")
        return redirect(url_for("index"))

    return render_template("login.html", email=email_preenchido)


@app.route("/logout")
def logout():
    session.clear()
    flash("Você saiu da sua conta.", "info")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nome = (request.form.get("nome") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        senha = request.form.get("senha") or ""
        confirmar_senha = request.form.get("confirmar_senha") or ""
        funcao = (request.form.get("funcao") or "comum").strip().lower()
        if funcao not in ("comum", "admin"):
            funcao = "comum"

        if not nome or not email or not senha:
            flash("Nome, e-mail e senha são obrigatórios.", "error")
            return render_template("register.html", nome=nome, email=email, funcao=funcao)

        if confirmar_senha and senha != confirmar_senha:
            flash("As senhas não coincidem.", "error")
            return render_template("register.html", nome=nome, email=email, funcao=funcao)

        if find_user_by_email(email):
            flash("Este e-mail já está cadastrado.", "error")
            return render_template("register.html", nome=nome, email=email, funcao=funcao)

        users = load_users()
        novo_id = get_next_id(users)

        foto_caminho = "static/images/default_avatar.png"
        arquivo = request.files.get("foto_perfil")
        if arquivo and arquivo.filename and allowed_file(arquivo.filename):
            ext = arquivo.filename.rsplit(".", 1)[1].lower()
            nome_arquivo = secure_filename(f"perfil_{novo_id}.{ext}")
            destino = os.path.join(UPLOAD_FOLDER, nome_arquivo)
            arquivo.save(destino)
            foto_caminho = f"static/uploads/{nome_arquivo}"

        novo_usuario = {
            "id": novo_id,
            "nome": nome,
            "email": email,
            "senha_hash": generate_password_hash(senha, method="pbkdf2:sha256"),
            "foto_perfil": foto_caminho,
            "data_cadastro": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "funcao": funcao,
            "excluido": False,
        }

        users.append(novo_usuario)
        save_users(users)

        flash("Cadastro concluído com sucesso! Faça login para continuar.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", nome="", email="", funcao="comum")


@app.route("/profile")
@app.route("/profile/<nome>")
@login_required
def profile(nome=None):
    user = find_user_by_id(session.get("user_id"))
    if not user or user.get("excluido") is True:
        session.clear()
        return make_response(render_template("erro_401.html"), 401)

    dados = safe_user_dict(user)
    dados["nome_exibido"] = request.args.get("nome") or nome or dados["nome"]
    dados["email_exibido"] = request.args.get("email") or dados["email"]
    dados["idade"] = request.args.get("idade", 25)
    dados["peso"] = request.args.get("peso", 70.5)
    dados["altura"] = request.args.get("altura", 1.75)
    metas = [
        "Calcular o IMC mensalmente",
        "Praticar atividade física 3x por semana",
        "Manter uma alimentação balanceada",
    ]
    return render_template("profile.html", usuario=dados, metas=metas)


@app.route("/editar_usuario", methods=["GET", "POST"])
@app.route("/editar_usuario/<int:alvo_id>", methods=["GET", "POST"])
@login_required
def editar_usuario(alvo_id=None):
    logado = find_user_by_id(session.get("user_id"))
    if not logado or logado.get("excluido") is True:
        session.clear()
        return make_response(render_template("erro_401.html"), 401)

    if alvo_id is not None and alvo_id != logado["id"] and logado.get("funcao") != "admin":
        return make_response(render_template("erro_403.html"), 403)

    target_id = alvo_id if alvo_id is not None else logado["id"]
    users = load_users()
    idx = next((i for i, u in enumerate(users) if u.get("id") == target_id), None)
    if idx is None:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("profile"))

    alvo = users[idx]

    if request.method == "POST":
        acao = request.form.get("acao") or "salvar"

        if acao == "excluir":
            alvo["excluido"] = True
            save_users(users)
            if alvo["id"] == logado["id"]:
                session.clear()
                flash("Sua conta foi excluída.", "info")
                return redirect(url_for("login"))
            flash("Conta marcada como excluída.", "success")
            return redirect(url_for("admin_dashboard"))

        if acao == "reativar" and logado.get("funcao") == "admin":
            alvo["excluido"] = False
            save_users(users)
            flash("Conta reativada.", "success")
            return redirect(url_for("admin_dashboard"))

        novo_nome = (request.form.get("nome") or alvo.get("nome") or "").strip()
        novo_email = (request.form.get("email") or alvo.get("email") or "").strip().lower()
        nova_senha = request.form.get("nova_senha") or ""
        nova_funcao = (request.form.get("funcao") or alvo.get("funcao") or "comum").strip().lower()
        if nova_funcao not in ("comum", "admin"):
            nova_funcao = alvo.get("funcao", "comum")

        if not novo_nome or not novo_email:
            flash("Nome e e-mail não podem ficar em branco.", "error")
            return render_template("editar_usuario.html", usuario=safe_user_dict(alvo))

        for u in users:
            if u.get("id") != alvo["id"] and (u.get("email") or "").strip().lower() == novo_email:
                flash("Este e-mail já está sendo usado por outro usuário.", "error")
                return render_template("editar_usuario.html", usuario=safe_user_dict(alvo))

        arquivo = request.files.get("foto_perfil")
        if arquivo and arquivo.filename and allowed_file(arquivo.filename):
            ext = arquivo.filename.rsplit(".", 1)[1].lower()
            nome_arquivo = secure_filename(f"perfil_{alvo['id']}.{ext}")
            destino = os.path.join(UPLOAD_FOLDER, nome_arquivo)
            arquivo.save(destino)
            alvo["foto_perfil"] = f"static/uploads/{nome_arquivo}"

        alvo["nome"] = novo_nome
        alvo["email"] = novo_email
        if logado.get("funcao") == "admin":
            alvo["funcao"] = nova_funcao
        if nova_senha.strip():
            alvo["senha_hash"] = generate_password_hash(nova_senha, method="pbkdf2:sha256")

        save_users(users)

        if alvo["id"] == logado["id"]:
            session["email"] = alvo["email"]
            session["funcao"] = alvo["funcao"]

        flash("Dados atualizados com sucesso!", "success")
        if logado.get("funcao") == "admin" and alvo["id"] != logado["id"]:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("profile"))

    return render_template("editar_usuario.html", usuario=safe_user_dict(alvo))


@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin_dashboard", methods=["GET", "POST"])
@admin_required
def admin_dashboard():
    users = load_users()

    if request.method == "POST":
        acao = request.form.get("acao")
        uid = int(request.form.get("user_id", 0))
        if acao == "excluir":
            for u in users:
                if u.get("id") == uid:
                    u["excluido"] = True
            save_users(users)
            if uid == session.get("user_id"):
                session.clear()
                return redirect(url_for("login"))
            flash("Usuário marcado como excluído.", "success")
        elif acao == "reativar":
            for u in users:
                if u.get("id") == uid:
                    u["excluido"] = False
            save_users(users)
            flash("Usuário reativado.", "success")
        return redirect(url_for("admin_dashboard"))

    busca = (request.args.get("q") or "").strip().lower()
    filtrados = [
        safe_user_dict(u)
        for u in users
        if not busca
        or busca in str(u.get("id", "")).lower()
        or busca in (u.get("nome") or "").lower()
        or busca in (u.get("email") or "").lower()
    ]

    total_usuarios = len(users)
    ativos = sum(1 for u in users if not u.get("excluido"))
    excluidos = sum(1 for u in users if u.get("excluido"))
    admins = sum(1 for u in users if u.get("funcao") == "admin" and not u.get("excluido"))

    stats = {
        "total": total_usuarios,
        "ativos": ativos,
        "excluidos": excluidos,
        "admins": admins,
    }
    return render_template("admin_dashboard.html", usuarios=filtrados, stats=stats, busca=busca)


@app.route("/math", methods=["GET", "POST"])
@app.route("/math/<op>/<a>/<b>", methods=["GET", "POST"])
def math_view(op=None, a=None, b=None):
    if request.method == "POST":
        op = request.form.get("operacao") or op or "soma"
        a = request.form.get("a") if request.form.get("a") is not None else a
        b = request.form.get("b") if request.form.get("b") is not None else b
        return redirect(url_for("math_view", op=op, a=a, b=b))

    op_raw = (op or request.args.get("op") or "soma").strip().lower()
    a_raw = a if a is not None else request.args.get("a")
    b_raw = b if b is not None else request.args.get("b")

    mapa_ops = {
        "soma": ("Soma", "+"),
        "+": ("Soma", "+"),
        "subtracao": ("Subtração", "-"),
        "subtração": ("Subtração", "-"),
        "-": ("Subtração", "-"),
        "multiplicacao": ("Multiplicação", "×"),
        "multiplicação": ("Multiplicação", "×"),
        "x": ("Multiplicação", "×"),
        "*": ("Multiplicação", "×"),
        "divisao": ("Divisão", "÷"),
        "divisão": ("Divisão", "÷"),
        "/": ("Divisão", "÷"),
        "÷": ("Divisão", "÷"),
    }

    nome_op, simbolo = mapa_ops.get(op_raw, ("Soma", "+"))

    erro = None
    resultado = None
    num_a = None
    num_b = None

    try:
        num_a = float(str(a_raw).replace(",", "."))
        num_b = float(str(b_raw).replace(",", "."))

        if simbolo == "+":
            resultado = num_a + num_b
        elif simbolo == "-":
            resultado = num_a - num_b
        elif simbolo == "×":
            resultado = num_a * num_b
        elif simbolo == "÷":
            if num_b == 0:
                erro = "Divisão por zero não é permitida."
            else:
                resultado = num_a / num_b
    except (TypeError, ValueError):
        erro = "Informe dois números válidos para realizar o cálculo."

    if isinstance(resultado, float) and resultado.is_integer():
        resultado = int(resultado)
    if isinstance(num_a, float) and num_a.is_integer():
        num_a = int(num_a)
    if isinstance(num_b, float) and num_b.is_integer():
        num_b = int(num_b)

    return render_template(
        "math.html",
        nome_op=nome_op,
        simbolo=simbolo,
        op_slug=op_raw,
        a=num_a if num_a is not None else a_raw,
        b=num_b if num_b is not None else b_raw,
        resultado=resultado,
        erro=erro,
    )


@app.route("/imc", methods=["GET", "POST"])
@app.route("/imc/<peso>/<altura>", methods=["GET", "POST"])
def imc_view(peso=None, altura=None):
    if request.method == "POST":
        p = request.form.get("peso") or peso
        h = request.form.get("altura") or altura
        idade = request.form.get("idade", 25)
        sexo = request.form.get("sexo", "masculino")
        return redirect(url_for("imc_view", peso=p, altura=h, idade=idade, sexo=sexo))

    p_raw = peso if peso is not None else request.args.get("peso")
    h_raw = altura if altura is not None else request.args.get("altura")
    idade_raw = request.args.get("idade", 25)
    sexo_raw = request.args.get("sexo", "masculino")

    dados = None
    erro = None

    try:
        p_val = float(str(p_raw).replace(",", "."))
        h_val = float(str(h_raw).replace(",", "."))
        idade_val = int(float(str(idade_raw or 25)))
        if p_val <= 0 or h_val <= 0:
            erro = "Peso e altura devem ser maiores que zero."
        else:
            dados = calcular_imc_dados(p_val, h_val, idade_val, sexo_raw)
    except (TypeError, ValueError):
        erro = "Preencha peso e altura válidos para calcular o IMC."

    return render_template("imc.html", dados=dados, erro=erro)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
