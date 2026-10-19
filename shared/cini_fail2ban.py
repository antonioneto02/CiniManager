"""cini_fail2ban (Python) - mesmo formato de log do cini-fail2ban.js, lido pelo IPBan do host.

FONTE UNICA: C:\\Projetos\\CiniManager\\shared\\cini_fail2ban.py
Copia em <App>/security/cini_fail2ban.py (sync-fail2ban.ps1). Sem dependencias externas.

Flask:     from security.cini_fail2ban import install_flask; install_flask(app, 'nome', login_paths=['/login'])
Django:    MIDDLEWARE = ['security.cini_fail2ban.DjangoMiddleware', ...]  + settings F2B_APP_NAME / F2B_LOGIN_PATHS
Streamlit: from security.cini_fail2ban import log_login_fail_streamlit; log_login_fail_streamlit('nome', usuario)
"""
import datetime
import os
import re
import threading
import time

LOG_DIR = os.environ.get('F2B_LOG_DIR') or os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs', 'security')
KEEP_DAYS = 14

SCANNER_PATTERNS = [re.compile(p, re.I) for p in (
    r'/\.(env|git|svn|hg|aws|ssh|docker|vscode|idea|htaccess|htpasswd|DS_Store)(/|$|\.)',
    r'\.(php\d?|phtml|asp|aspx|jsp|cgi|pl|sh|bak|sql|swp)$',
    r'/wp-(admin|login|content|includes|config)',
    r'/(phpmyadmin|pma|myadmin|adminer|xmlrpc|cgi-bin|boaform|HNAP1|actuator|solr|jenkins|manager/html|server-status|telescope|_ignition)(/|$)',
    r'/vendor/phpunit',
    r'/(config|credentials|secrets|backup|dump|database)\.(json|ya?ml|xml|ini|zip|tar|gz|rar)$',
    r'(\.\./|\.\.\\|%2e%2e(%2f|%5c|/|\\))',
)]
LOGIN_FAIL_REDIRECT = re.compile(r'[?&](error=invalid_credentials|erro=1)(&|$)', re.I)
THROTTLE = {'SCANNER': 2, 'RATE_LIMIT': 60, 'LOGIN_FAIL': 0}

_lock = threading.Lock()
_ultimo = {}
_limpeza = ''


def _clean(valor, maximo):
    if valor is None or valor == '':
        return '-'
    return re.sub(r'[\s"\']+', '_', str(valor))[:maximo]


def _limpar_antigos():
    global _limpeza
    dia = datetime.date.today().isoformat()
    if _limpeza == dia:
        return
    _limpeza = dia
    limite = time.time() - KEEP_DAYS * 86400
    try:
        for nome in os.listdir(LOG_DIR):
            m = re.match(r'^(?:scanner|rate_limit|login_fail)-(\d{4}-\d{2}-\d{2})\.log$', nome)
            if m and time.mktime(time.strptime(m.group(1), '%Y-%m-%d')) < limite:
                os.remove(os.path.join(LOG_DIR, nome))
    except OSError:
        pass


def registrar(tipo, ip, app_name, user=None, path=None):
    ip = (ip or 'desconhecido').replace('::ffff:', '')
    agora = time.time()
    with _lock:
        throttle = THROTTLE.get(tipo, 0)
        if throttle:
            chave = f'{tipo}:{ip}'
            if agora - _ultimo.get(chave, 0) < throttle:
                return
            _ultimo[chave] = agora
            if len(_ultimo) > 5000:
                _ultimo.clear()
        ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') + f'{int(agora * 1000) % 1000:03d}Z'
        linha = (f'{ts} CINI-F2B type={tipo} ip={ip} app={_clean(app_name, 60)} '
                 f'user={_clean(user, 60)} path={_clean((path or "").split("?")[0], 200)}\n')
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            arquivo = os.path.join(LOG_DIR, f'{tipo.lower()}-{datetime.datetime.now(datetime.timezone.utc).date().isoformat()}.log')
            with open(arquivo, 'a', encoding='utf-8') as f:
                f.write(linha)
            _limpar_antigos()
        except OSError as e:
            print(f'[cini-fail2ban] Falha ao gravar log de seguranca: {e}')


def is_scanner(path_com_query):
    path = (path_com_query or '').split('?')[0]
    return any(p.search(path) for p in SCANNER_PATTERNS) or bool(re.search(r'(\.\./|%2e%2e)', path_com_query or '', re.I))


def _falhou_login(status, location):
    return status in (401, 403) or (300 <= status < 400 and bool(LOGIN_FAIL_REDIRECT.search(location or '')))


REDES_CINI = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10',
              '177.104.136.227/32', '200.225.247.91/32', '200.225.247.159/32']


def ip_da_cini(ip):
    import ipaddress
    try:
        end = ipaddress.ip_address((ip or '').replace('::ffff:', ''))
    except ValueError:
        return False
    if end.is_loopback:
        return True
    return any(end in ipaddress.ip_network(r) for r in REDES_CINI if end.version == 4)


def install_flask(app, app_name, login_paths=(), rate_limit=True, somente_rede_cini=False, publicas=('/health',)):
    """somente_rede_cini=True: rotas so para IP da Cini, exceto `publicas` (caminhos exatos)."""
    from flask import request, abort
    caminhos = {p.rstrip('/').lower() for p in login_paths}
    livres = {p.rstrip('/') or '/' for p in publicas}

    @app.before_request
    def _f2b_before():
        if is_scanner(request.full_path if request.query_string else request.path):
            registrar('SCANNER', request.remote_addr, app_name, path=request.path)
            abort(404)
        if somente_rede_cini and not ip_da_cini(request.remote_addr) \
                and (request.path.rstrip('/') or '/') not in livres:
            registrar('RATE_LIMIT', request.remote_addr, app_name, path=request.path)
            abort(403)

    @app.after_request
    def _f2b_after(resp):
        if resp.status_code == 429:
            if rate_limit:
                registrar('RATE_LIMIT', request.remote_addr, app_name, path=request.path)
        elif request.method == 'POST' and request.path.rstrip('/').lower() in caminhos \
                and _falhou_login(resp.status_code, resp.headers.get('Location')):
            corpo = request.form or (request.get_json(silent=True) or {})
            user = corpo.get('username') or corpo.get('usuario') or corpo.get('login') if hasattr(corpo, 'get') else None
            registrar('LOGIN_FAIL', request.remote_addr, app_name, user, request.path)
        return resp


def log_login_fail_flask(app_name, user=None):
    from flask import request
    registrar('LOGIN_FAIL', request.remote_addr, app_name, user, request.path)


# ---------------- Django ----------------
class DjangoMiddleware:
    def __init__(self, get_response):
        from django.conf import settings
        self.get_response = get_response
        self.app_name = getattr(settings, 'F2B_APP_NAME', 'django-app')
        self.login_paths = {p.rstrip('/').lower() for p in getattr(settings, 'F2B_LOGIN_PATHS', [])}
        self.rate_limit = getattr(settings, 'F2B_RATE_LIMIT', True)
        # Prefixos so para a rede da Cini (ex.: ['/admin/'] — painel do Django)
        self.prefixos_internos = tuple(getattr(settings, 'F2B_PREFIXOS_INTERNOS', []))

    def __call__(self, request):
        from django.http import HttpResponseNotFound, HttpResponseForbidden
        ip = request.META.get('REMOTE_ADDR')
        if is_scanner(request.get_full_path()):
            registrar('SCANNER', ip, self.app_name, path=request.path)
            return HttpResponseNotFound()
        if self.prefixos_internos and request.path.startswith(self.prefixos_internos) and not ip_da_cini(ip):
            registrar('RATE_LIMIT', ip, self.app_name, path=request.path)
            return HttpResponseForbidden()
        resp = self.get_response(request)
        if resp.status_code == 429:
            if self.rate_limit:
                registrar('RATE_LIMIT', ip, self.app_name, path=request.path)
        elif request.method == 'POST' and request.path.rstrip('/').lower() in self.login_paths \
                and _falhou_login(resp.status_code, resp.get('Location')):
            registrar('LOGIN_FAIL', ip, self.app_name, request.POST.get('username') or request.POST.get('usuario'), request.path)
        return resp


# ---------------- Streamlit ----------------
def log_login_fail_streamlit(app_name, user=None):
    """Chamar no ramo de senha errada. Precisa de streamlit >= 1.45 (st.context.ip_address)."""
    try:
        import streamlit as st
        ip = getattr(st.context, 'ip_address', None)
    except Exception:
        ip = None
    if ip:
        registrar('LOGIN_FAIL', ip, app_name, user, '/login')
