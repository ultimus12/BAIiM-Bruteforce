import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import os
import time # Utrzymano, aby wprowadzić opóźnienie po nieudanym logowaniu

app = Flask(__name__)
# Klucz sesji jest potrzebny do przechowywania informacji o zalogowanym użytkowniku
app.secret_key = os.urandom(24) 

DATABASE = 'database.db'

# --- Konfiguracja Bazy Danych ---

def get_db():
    """Nawiązuje połączenie z bazą danych."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Tworzy tabelę użytkowników i dodaje użytkownika 'user1'."""
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
            # Hashowanie hasła 'aaay' (ZMIENIONE)
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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        db.close()

        if user and check_password_hash(user['password_hash'], password):
            # Logowanie pomyślne: zapisz użytkownika w sesji
            session['username'] = user['username']
            return redirect(url_for('witaj'))
        else:
            # Logowanie niepomyślne - Wprowadź opóźnienie 3 sekundy
            time.sleep(3) # <--- Opóźnienie 3 sekundy
            error = 'Blad uzytkownika lub hasla'

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