#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Servidor local da Loja (Amy Sam Doceria).

- Roda 100% na sua maquina, sem enviar nada para a internet.
- Usa somente a biblioteca padrao do Python (nada de 'pip install').
- Guarda produtos, configuracoes e o login do administrador em 'loja.db' (SQLite).
- Login do administrador validado no servidor (senha protegida com PBKDF2-SHA256 + sal).

Como usar:
    python3 server.py               -> abre em http://0.0.0.0:8000 (acesso pela rede local)
    python3 server.py 8080          -> escolhe outra porta
    python3 server.py 8000 127.0.0.1-> restringe o acesso so a esta maquina

Depois abra no navegador:  http://localhost:8000
"""
import http.server
import socketserver
import json
import sqlite3
import os
import sys
import hashlib
import hmac
import secrets
import socket
import threading

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'loja.db')
HTML_PATH = os.path.join(BASE_DIR, 'loja.html')

# ---- Cardapio padrao (semeado na primeira execucao) ----
CONFIG_PADRAO = {
    'loja': 'Amy Sam Doceria',
    'whats': '5585992225804',
    'instagram': 'amysam_doceria',
    'produtos': [
        {'id': 1, 'nome': '\U0001F30B Vulc\u00e3o Massa Amanteigada', 'preco': 15.0, 'img': '', 'cat': 'Bolo', 'sabores': ['Ninho', 'Brigadeiro', 'Dois amores', 'Ninho com morango']},
        {'id': 2, 'nome': '\U0001F955 Vulc\u00e3o Cenoura com Chocolate', 'preco': 15.0, 'img': '', 'cat': 'Bolo', 'sabores': []},
        {'id': 3, 'nome': '\U0001F36B Vulc\u00e3o Massa de Chocolate', 'preco': 16.0, 'img': '', 'cat': 'Bolo', 'sabores': []},
        {'id': 4, 'nome': '\U0001F34B Vulc\u00e3o Lim\u00e3o com Chocolate Branco', 'preco': 16.0, 'img': '', 'cat': 'Bolo', 'sabores': []},
        {'id': 5, 'nome': '\U0001F49B Vulc\u00e3o Maracuj\u00e1', 'preco': 16.0, 'img': '', 'cat': 'Bolo', 'sabores': []},
        {'id': 6, 'nome': '\U0001F36B Vulc\u00e3o Ninho com Nutella', 'preco': 18.0, 'img': '', 'cat': 'Bolo', 'sabores': []},
        {'id': 7, 'nome': '\U0001F36A Vulc\u00e3o Oreo', 'preco': 18.0, 'img': '', 'cat': 'Bolo', 'sabores': []},
        {'id': 8, 'nome': '\U0001F90D Vulc\u00e3o Ouro Branco', 'preco': 18.0, 'img': '', 'cat': 'Bolo', 'sabores': []},
        {'id': 9, 'nome': '\U0001F49B\U0001F36B Vulc\u00e3o Maracuj\u00e1 com Nutella', 'preco': 18.0, 'img': '', 'cat': 'Bolo', 'sabores': []},
        {'id': 10, 'nome': '\u2728 Vulc\u00e3o Kinder Bueno (Novidade)', 'preco': 20.0, 'img': '', 'cat': 'Bolo', 'sabores': []},
        {'id': 11, 'nome': '\u2764\ufe0f Vulc\u00e3o Red Velvet (Novidade)', 'preco': 18.0, 'img': '', 'cat': 'Bolo', 'sabores': []},
        {'id': 12, 'nome': '\u2728 Vulc\u00e3o Biscoff (Novidade)', 'preco': 20.0, 'img': '', 'cat': 'Bolo', 'sabores': []},
        {'id': 13, 'nome': '\U0001FA99 Pote Massa Amanteigada', 'preco': 12.0, 'img': '', 'cat': 'Bolo em Pote', 'sabores': ['Ninho', 'Brigadeiro', 'Ninho com morango', 'Cenoura com brigadeiro', 'Dois amores']},
        {'id': 14, 'nome': '\U0001F34B Pote Lim\u00e3o com Chocolate Branco', 'preco': 13.0, 'img': '', 'cat': 'Bolo em Pote', 'sabores': []},
        {'id': 15, 'nome': '\U0001F36B Pote Massa de Chocolate 100%', 'preco': 13.0, 'img': '', 'cat': 'Bolo em Pote', 'sabores': ['Oreo', 'Ninho', 'Brigadeiro', 'Ouro Branco', 'Dois amores', 'Maracuj\u00e1']},
    ],
}

_db_lock = threading.Lock()
_sessoes = {}  # token -> usuario


def conectar():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with _db_lock:
        con = conectar()
        con.execute('CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK (id=1), dados TEXT)')
        con.execute('CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK (id=1), usuario TEXT, sal TEXT, senha_hash TEXT)')
        row = con.execute('SELECT dados FROM config WHERE id=1').fetchone()
        if row is None:
            con.execute('INSERT INTO config (id, dados) VALUES (1, ?)', (json.dumps(CONFIG_PADRAO, ensure_ascii=False),))
        con.commit()
        con.close()


def ler_config():
    with _db_lock:
        con = conectar()
        row = con.execute('SELECT dados FROM config WHERE id=1').fetchone()
        con.close()
    if not row:
        return dict(CONFIG_PADRAO)
    try:
        return json.loads(row['dados'])
    except Exception:
        return dict(CONFIG_PADRAO)


def gravar_config(dados):
    with _db_lock:
        con = conectar()
        con.execute('UPDATE config SET dados=? WHERE id=1', (json.dumps(dados, ensure_ascii=False),))
        con.commit()
        con.close()


def tem_admin():
    with _db_lock:
        con = conectar()
        row = con.execute('SELECT 1 FROM admin WHERE id=1').fetchone()
        con.close()
    return row is not None


def _hash_senha(senha, sal):
    return hashlib.pbkdf2_hmac('sha256', senha.encode('utf-8'), bytes.fromhex(sal), 200000).hex()


def criar_admin(usuario, senha):
    sal = secrets.token_hex(16)
    h = _hash_senha(senha, sal)
    with _db_lock:
        con = conectar()
        con.execute('INSERT OR REPLACE INTO admin (id, usuario, sal, senha_hash) VALUES (1, ?, ?, ?)', (usuario, sal, h))
        con.commit()
        con.close()


def atualizar_admin(usuario, senha=None):
    with _db_lock:
        con = conectar()
        row = con.execute('SELECT sal, senha_hash FROM admin WHERE id=1').fetchone()
        if row is None:
            con.close()
            return False
        if senha:
            sal = secrets.token_hex(16)
            h = _hash_senha(senha, sal)
        else:
            sal = row['sal']
            h = row['senha_hash']
        con.execute('UPDATE admin SET usuario=?, sal=?, senha_hash=? WHERE id=1', (usuario, sal, h))
        con.commit()
        con.close()
    return True


def verificar_login(usuario, senha):
    with _db_lock:
        con = conectar()
        row = con.execute('SELECT usuario, sal, senha_hash FROM admin WHERE id=1').fetchone()
        con.close()
    if row is None:
        return False
    if usuario != row['usuario']:
        return False
    calc = _hash_senha(senha, row['sal'])
    return hmac.compare_digest(calc, row['senha_hash'])


def usuario_admin():
    with _db_lock:
        con = conectar()
        row = con.execute('SELECT usuario FROM admin WHERE id=1').fetchone()
        con.close()
    return row['usuario'] if row else ''


# ---------------- HTTP ----------------
COOKIE = 'loja_sessao'


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # silencia o log padrao

    def _cookies(self):
        raw = self.headers.get('Cookie', '')
        out = {}
        for parte in raw.split(';'):
            if '=' in parte:
                k, v = parte.strip().split('=', 1)
                out[k] = v
        return out

    def _usuario_logado(self):
        tok = self._cookies().get(COOKIE, '')
        return _sessoes.get(tok)

    def _json(self, obj, status=200, extra_headers=None):
        corpo = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(corpo)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(corpo)

    def _corpo_json(self):
        try:
            n = int(self.headers.get('Content-Length', 0))
            if n <= 0:
                return {}
            return json.loads(self.rfile.read(n).decode('utf-8'))
        except Exception:
            return {}

    # ---- GET ----
    def do_GET(self):
        if self.path.split('?')[0] == '/api/estado':
            usuario = self._usuario_logado()
            self._json({
                'temAdmin': tem_admin(),
                'logado': usuario is not None,
                'usuario': usuario or '',
                'config': ler_config(),
            })
            return
        # servir a pagina
        if self.path in ('/', '/index.html', '/loja.html'):
            self._servir_html()
            return
        self.send_error(404)

    def _servir_html(self):
        try:
            with open(HTML_PATH, 'rb') as f:
                corpo = f.read()
        except FileNotFoundError:
            self.send_error(500, 'loja.html nao encontrado')
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    # ---- POST ----
    def do_POST(self):
        rota = self.path.split('?')[0]
        dados = self._corpo_json()

        if rota == '/api/setup':
            if tem_admin():
                self._json({'ok': False, 'erro': 'existe'}, 403)
                return
            usuario = (dados.get('usuario') or '').strip()
            senha = dados.get('senha') or ''
            if len(usuario) < 3 or len(senha) < 4:
                self._json({'ok': False, 'erro': 'dados'}, 400)
                return
            criar_admin(usuario, senha)
            tok = secrets.token_hex(24)
            _sessoes[tok] = usuario
            self._json({'ok': True}, 200, [('Set-Cookie', f'{COOKIE}={tok}; Path=/; HttpOnly; SameSite=Strict')])
            return

        if rota == '/api/login':
            usuario = (dados.get('usuario') or '').strip()
            senha = dados.get('senha') or ''
            if verificar_login(usuario, senha):
                tok = secrets.token_hex(24)
                _sessoes[tok] = usuario
                self._json({'ok': True}, 200, [('Set-Cookie', f'{COOKIE}={tok}; Path=/; HttpOnly; SameSite=Strict')])
            else:
                self._json({'ok': False}, 401)
            return

        if rota == '/api/logout':
            tok = self._cookies().get(COOKIE, '')
            _sessoes.pop(tok, None)
            self._json({'ok': True}, 200, [('Set-Cookie', f'{COOKIE}=; Path=/; Max-Age=0')])
            return

        if rota == '/api/config':
            if self._usuario_logado() is None:
                self._json({'ok': False, 'erro': 'auth'}, 401)
                return
            cfg = dados.get('config')
            if not isinstance(cfg, dict):
                self._json({'ok': False, 'erro': 'dados'}, 400)
                return
            cfg.pop('admHash', None)
            cfg.pop('admUser', None)
            gravar_config(cfg)
            self._json({'ok': True})
            return

        if rota == '/api/credenciais':
            if self._usuario_logado() is None:
                self._json({'ok': False, 'erro': 'auth'}, 401)
                return
            usuario = (dados.get('usuario') or '').strip()
            senha = dados.get('senha')
            if len(usuario) < 3 or (senha and len(senha) < 4):
                self._json({'ok': False, 'erro': 'dados'}, 400)
                return
            atualizar_admin(usuario, senha if senha else None)
            # atualiza o nome de usuario nas sessoes ativas
            for t in list(_sessoes.keys()):
                _sessoes[t] = usuario
            self._json({'ok': True})
            return

        self.send_error(404)


class Servidor(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def main():
    porta = 8000
    host = '0.0.0.0'
    # Em hospedagens na nuvem (Render, Railway, Fly, etc.) a porta vem na
    # variavel de ambiente PORT. Usamos ela automaticamente se existir.
    if os.environ.get('PORT'):
        try:
            porta = int(os.environ['PORT'])
        except ValueError:
            pass
    if len(sys.argv) >= 2:
        try:
            porta = int(sys.argv[1])
        except ValueError:
            pass
    if len(sys.argv) >= 3:
        host = sys.argv[2]
    init_db()
    srv = Servidor((host, porta), Handler)
    print('=' * 54)
    print('  Loja Amy Sam Doceria - servidor local iniciado')
    print('=' * 54)
    print('  Nesta maquina:   http://localhost:%d' % porta)
    if host == '0.0.0.0':
        print('  Na rede local:   http://%s:%d' % (ip_local(), porta))
        print('  (use esse endereco em celulares/computadores na mesma rede Wi-Fi)')
    print('')
    print('  Para PARAR o servidor: pressione Ctrl+C nesta janela.')
    print('=' * 54)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\nServidor encerrado.')
        srv.shutdown()


if __name__ == '__main__':
    main()
