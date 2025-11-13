import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import os
import time
import logging
import json
from datetime import datetime

# --- Konfiguracja Flask i Loggera ---
app = Flask(__name__)
app.secret_key = os.urandom(24) 
DATABASE = 'database.db'

LOG_DATETIME_FORMAT = '%Y%m%d_%H%M' 
current_time_str = datetime.now().strftime(LOG_DATETIME_FORMAT)
LOG_FILE = f'auth_attempts_{current_time_str}.jsonl'

FAILURE_DELAY_SECONDS = 3 # Stała do opóźnienia

# --- Ustawienie loggera, który zapisuje czyste linie JSON ---
def setup_json_logger(log_filename):
    log_formatter = logging.Formatter('%(message)s')
    log_handler = logging.FileHandler(log_filename, mode='a')
    log_handler.setFormatter(log_formatter)

    logger = logging.getLogger('access_logger')
    logger.setLevel(logging.INFO)
    if not logger.handlers: # Zapobieganie podwójnemu dodawaniu handlerów
        logger.addHandler(log_handler)
    return logger

access_logger = setup_json_logger(LOG_FILE)


# --- Konfiguracja Bazy Danych (Zmienione hasło na 'aaay' zgodnie z notatkami) ---

def get_db():
    """Nawiązuje połączenie z bazą danych."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Tworzy tabelę użytkowników i dodaje użytkownika 'user1' (hasło: 'aaay')."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Stwórz tabelę, jeśli nie istnieje
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
        ''')
        
        # Sprawdź, czy user1 już istnieje
        cursor.execute("SELECT * FROM users WHERE username = 'user1'")
        if not cursor.fetchone():
            # Hashowanie hasła 'aaay'
            hashed_password = generate_password_hash('aaay')
            
            # Wstawienie użytkownika 'user1' z zahashowanym hasłem
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ('user1', hashed_password)
            )
            print("Utworzono użytkownika 'user1' z hasłem 'aaay'.")
        
        db.commit()
        db.close()


# --- Trasy (Routes) Aplikacji ---

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('witaj'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    delay = 0 # Domyślne opóźnienie
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        db.close()

        # Przygotowanie danych do logowania
        log_data = {
            'timestamp': time.time(),
            'datetime': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime()),
            'ip_address': request.remote_addr,
            'endpoint': '/login',
            'attempted_username': username,
            'result': 'FAILURE',
            'reason': 'Blad uzytkownika lub hasla', 
            'delay_s': 0 # Wartość tymczasowa
        }

        if user and check_password_hash(user['password_hash'], password):
            # Logowanie pomyślne
            log_data['result'] = 'SUCCESS'
            log_data['reason'] = 'Login successful'
            session['username'] = user['username']
            
        else:
            # Logowanie niepomyślne - Wprowadź opóźnienie
            delay = FAILURE_DELAY_SECONDS
            time.sleep(delay) 
            error = log_data['reason']
        
        log_data['delay_s'] = delay # Zapisz rzeczywiste opóźnienie

        # Zapis logu w formacie JSON Lines
        access_logger.info(json.dumps(log_data))

        if log_data['result'] == 'SUCCESS':
             return redirect(url_for('witaj'))

    return render_template('login.html', error=error)

@app.route('/witaj')
def witaj():
    if 'username' in session:
        return render_template('witaj.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None) # Usuń użytkownika z sesji
    return redirect(url_for('login'))

# Uruchomienie inicjalizacji bazy danych
if __name__ == '__main__':
    # Ważne: Jeśli baza danych już istnieje, musisz ją usunąć (plik database.db),
    # aby zainicjalizować nowego użytkownika z hasłem 'aaay' przy ponownym uruchomieniu serwera.
    init_db() 
    app.run(debug=True, port=5000, host='0.0.0.0') # Uruchom serwer Flask