"""Учебный сервис опросов. Начните чтение с README.html."""
# Стандартная библиотека Python уже входит в поставку языка.
# csv готовит таблицу для скачивания, io даёт временный текстовый буфер в памяти.
# json переводит списки и словари в текст и обратно, sqlite3 работает с файлом базы.
# os читает настройки запуска, secrets создаёт случайные ключи и ссылки. ttttt
# олоололопше
import csv
import io
import json
import os
import secrets
import sqlite3
from functools import wraps
from contextlib import contextmanager
from pathlib import Path

# Flask связывает адреса с функциями. request содержит текущий запрос браузера,
# session хранит состояние конкретного браузера, а redirect отправляет его на другой адрес.
# Werkzeug предоставляет функции для создания и проверки хеша пароля.
from flask import Flask, abort, redirect, render_template_string, request, session, url_for, Response
from werkzeug.security import check_password_hash, generate_password_hash

# Строим путь от расположения app.py, поэтому база окажется рядом с проектом
# даже при запуске из другой рабочей папки. При первом запуске создаём instance/.
ROOT = Path(__file__).parent
DATA = ROOT / 'instance'
DATA.mkdir(exist_ok=True)
# Ключ нужен Flask для подписи cookie сессии. Храним его в файле,
# чтобы после перезапуска сервера уже выданные сессии оставались действительными.
key_file = DATA / 'session.key'
if not key_file.exists():
    key_file.write_text(secrets.token_hex(32))
app = Flask(__name__)
app.secret_key = key_file.read_text()
# HttpOnly закрывает доступ к cookie из JavaScript. SameSite=Lax ограничивает
# отправку cookie при запросах с других сайтов. Размер входящего запроса ограничен 1 МиБ.
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', MAX_CONTENT_LENGTH=1024 * 1024)


# Благодаря @contextmanager можно писать with db() as c.
# Эта функция отвечает за открытие, завершение операции и закрытие соединения.
@contextmanager
def db():
    connection = sqlite3.connect(DATA / 'surveys.sqlite')
    # Row позволяет обращаться к полю по имени, например survey['title'].
    # Включаем внешние ключи, чтобы ответ мог ссылаться только на существующий опрос.
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys=ON')
    try:
        with connection:
            # Передаём соединение внутрь блока with у вызывающего кода.
            # Когда блок закончится, SQLite сохранит изменения или откатит их при исключении.
            yield connection
    finally:
        connection.close()


# При загрузке приложения создаём таблицы, которых ещё нет.
# admin хранит одну запись администратора. surveys хранит вопросы и статус публикации.
# answers хранит ответы. survey_id связывает каждый ответ с опросом.
# questions и payload — текстовые колонки, в которых лежат списки в формате JSON.
with db() as connection:
    connection.executescript('''
    CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), password TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS surveys (
        id INTEGER PRIMARY KEY, title TEXT NOT NULL, questions TEXT NOT NULL,
        published INTEGER NOT NULL DEFAULT 0, token TEXT UNIQUE NOT NULL);
    CREATE TABLE IF NOT EXISTS answers (
        id INTEGER PRIMARY KEY, survey_id INTEGER NOT NULL REFERENCES surveys(id),
        name TEXT NOT NULL, payload TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP);
    ''')


# CSRF-токен — случайное значение для проверки отправки формы.
# При показе формы шаблон кладёт токен в скрытое поле, а Flask хранит копию в сессии.
def csrf():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(24)
    return session['csrf']


# Flask вызывает эту функцию перед обработчиком адреса.
# Для POST сравниваем токен формы с токеном сессии. При несовпадении
# возвращаем 400, поэтому действие, например сохранение ответа, не выполнится.
@app.before_request
def protect_forms():
    if request.method == 'POST' and not secrets.compare_digest(request.form.get('csrf', ''), session.get('csrf', 'missing')):
        abort(400, 'Форма устарела. Обновите страницу.')


# Декоратор @admin_only оборачивает функцию страницы проверкой входа.
# Если вход выполнен, передаём функции все исходные аргументы, включая ID опроса.
# @wraps сохраняет имя исходной функции, которым Flask пользуется в url_for.
def admin_only(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('login'))
        return function(*args, **kwargs)
    return wrapped


# Общий HTML-каркас страницы содержит заголовок, стили и меню.
# Jinja вставляет значения из {{ ... }} и выполняет условия и циклы из {% ... %}.
# CONTENT обозначает место для HTML конкретной страницы.
BASE = '''<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{{ title }}</title>
<style>body{font:17px system-ui;background:#f4f2fa;color:#242133;max-width:850px;margin:35px auto;padding:0 18px}main{background:white;padding:28px;border-radius:16px}input,textarea,select,button{font:inherit;padding:9px;box-sizing:border-box}input[type=text],input[type=password],textarea{width:100%}textarea{min-height:90px}button{background:#6946b8;color:white;border:0;border-radius:7px;cursor:pointer}label{display:block;margin:12px 0}fieldset{margin:20px 0;border:1px solid #ddd;border-radius:8px}a{color:#6946b8}nav{margin-bottom:20px}small{color:#666}.error{color:#b02035}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px;text-align:left;white-space:pre-wrap}.scroll{overflow:auto}</style>
<nav><a href="/">Мои опросы</a>{% if session.get('admin') %}<form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf() }}"><button>Выйти</button></form>{% endif %}</nav>
<main><h1>{{ title }}</h1>{% if error %}<p class="error">{{ error }}</p>{% endif %}CONTENT</main></html>'''


# Подставляем фрагмент страницы и передаём шаблону данные.
# **context даёт каждой странице возможность передать свои имена, например questions.
def page(title, content, **context):
    return render_template_string(BASE.replace('CONTENT', content), title=title, csrf=csrf, **context)


# GET показывает форму входа. POST получает пароль и пробует войти.
# Пока таблица admin пуста, успешная отправка создаёт пароль администратора.
@app.route('/login', methods=['GET', 'POST'])
def login():
    with db() as c:
        administrator = c.execute('SELECT password FROM admin WHERE id=1').fetchone()
    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        # При первом входе проверяем длину и сохраняем хеш.
        # При следующих входах Werkzeug проверяет введённый пароль по этому хешу.
        if administrator is None:
            if len(password) < 12:
                error = 'Используйте пароль длиной от 12 символов.'
            else:
                with db() as c:
                    c.execute('INSERT INTO admin VALUES(1,?)', (generate_password_hash(password),))
        elif not check_password_hash(administrator['password'], password):
            error = 'Неверный пароль.'
        if error is None:
            # Начинаем состояние входа с чистой сессии, устанавливаем признак
            # администратора и отправляем браузер на главную страницу.
            session.clear()
            session['admin'] = True
            return redirect(url_for('index'))
    return page('Вход' if administrator else 'Создание пароля администратора', '''
    <form method="post"><input type="hidden" name="csrf" value="{{ csrf() }}">
    <label>Пароль<input type="password" name="password" required minlength="12"></label><button>Продолжить</button></form>''', error=error)


# При выходе очищаем всю сессию, включая признак администратора и токен формы.
@app.post('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.get('/')
@admin_only
# Для каждой строки опроса запрос дополнительно считает связанные ответы.
# Jinja выводит карточки от новых к старым и выбирает кнопку по статусу публикации.
def index():
    with db() as c:
        surveys = c.execute('SELECT s.*, (SELECT count(*) FROM answers WHERE survey_id=s.id) AS total FROM surveys s ORDER BY id DESC').fetchall()
    return page('Мои опросы', '''<a href="/new">Создать опрос</a>
    {% for s in surveys %}<fieldset><h2>{{ s.title }}</h2><p>{{ 'Опубликован' if s.published else 'Закрыт / черновик' }} · Ответов: {{ s.total }}</p>
    <a href="/edit/{{ s.id }}">Редактировать</a> · <a href="/results/{{ s.id }}">Результаты</a>
    <p>Ссылка участникам: <a href="/s/{{ s.token }}">{{ request.host_url }}s/{{ s.token }}</a></p>
    <form method="post" action="/toggle/{{ s.id }}"><input type="hidden" name="csrf" value="{{ csrf() }}"><button>{{ 'Закрыть' if s.published else 'Опубликовать' }}</button></form></fieldset>{% endfor %}''', surveys=surveys)


# Стартовые вопросы нового опроса. Каждый словарь содержит текст, тип,
# обязательность и варианты. Порядок элементов списка задаёт порядок вопросов.
EXAMPLE = [{'text': 'Что вам понравилось?', 'type': 'text', 'required': True, 'options': []},
           {'text': 'Оцените встречу', 'type': 'single', 'required': True, 'options': ['Отлично', 'Хорошо', 'Есть замечания']},
           {'text': 'Что обсудим в следующий раз?', 'type': 'multiple', 'required': False, 'options': ['Python', 'HTML', 'Базы данных']}]


# Один обработчик обслуживает создание и изменение. Для /new ID отсутствует,
# а для /edit/число Flask передаёт survey_id как целое число.
@app.route('/new', methods=['GET', 'POST'])
@app.route('/edit/<int:survey_id>', methods=['GET', 'POST'])
@admin_only
def edit(survey_id=None):
    with db() as c:
        survey = c.execute('SELECT * FROM surveys WHERE id=?', (survey_id,)).fetchone() if survey_id else None
        count = c.execute('SELECT count(*) FROM answers WHERE survey_id=?', (survey_id,)).fetchone()[0]
    if survey_id and survey is None:
        abort(404)
    # Ответы связаны с вопросами по порядку. После первого ответа блокируем правки,
    # чтобы изменение текста или порядка не меняло смысл собранных результатов.
    if count:
        return page('Редактирование закрыто', '<p>У опроса уже есть ответы. Создайте новый опрос, чтобы сохранить смысл результатов.</p>')
    # При редактировании превращаем JSON из базы в список Python.
    # При создании берём стартовый набор EXAMPLE и пустое название.
    questions = json.loads(survey['questions']) if survey else EXAMPLE
    title = survey['title'] if survey else ''
    error = None
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        try:
            # JavaScript отправил текст JSON в скрытом поле questions.
            # Читаем его и проверяем структуру на сервере, прежде чем писать в базу.
            questions = json.loads(request.form.get('questions', ''))
            if not title or len(title) > 200 or not isinstance(questions, list) or not 1 <= len(questions) <= 50:
                raise ValueError('Нужны название и от 1 до 50 вопросов.')
            # Сначала проверяем название и число вопросов, затем каждый вопрос.
            # У вариантов проверяем тип, непустой текст и отсутствие повторов.
            for q in questions:
                if not isinstance(q, dict) or q.get('type') not in ('text', 'single', 'multiple') or not isinstance(q.get('text'), str) or not q['text'].strip():
                    raise ValueError('Проверьте текст и тип вопросов.')
                options = q.get('options', [])
                if not isinstance(options, list) or any(not isinstance(x, str) or not x.strip() for x in options) or len(set(options)) != len(options):
                    raise ValueError('Варианты должны быть непустыми и различаться.')
                if q['type'] != 'text' and not 2 <= len(options) <= 30:
                    raise ValueError('У вопроса с выбором должно быть от 2 до 30 вариантов.')
            with db() as c:
                # UPDATE меняет существующую строку и закрывает приём ответов.
                # INSERT создаёт закрытый опрос со случайным токеном для ссылки.
                # Знаки ? — места для значений. SQLite получает значения отдельно.
                if survey:
                    c.execute('UPDATE surveys SET title=?,questions=?,published=0 WHERE id=?', (title, json.dumps(questions, ensure_ascii=False), survey_id))
                else:
                    c.execute('INSERT INTO surveys(title,questions,token) VALUES(?,?,?)', (title, json.dumps(questions, ensure_ascii=False), secrets.token_urlsafe(18)))
            return redirect(url_for('index'))
        # При ошибке показываем сообщение и снова выводим стартовый набор вопросов.
        # Название остаётся в переменной title и подставляется в форму.
        except (ValueError, TypeError) as exc:
            error = str(exc)
            questions = EXAMPLE
    # Шаблон готовит пустое место для карточек и скрытое поле для JSON.
    # JavaScript получает исходный список через фильтр tojson, строит карточки
    # и заполняет скрытое поле непосредственно перед отправкой формы.
    return page('Конструктор опроса', '''<form method="post" id="editor"><input type="hidden" name="csrf" value="{{ csrf() }}">
    <label>Название<input type="text" name="title" value="{{ survey_title }}" required maxlength="200"></label>
    <div id="questions"></div><button type="button" id="add">Добавить вопрос</button>
    <input type="hidden" name="questions" id="payload"><button>Сохранить черновик</button></form>
    <script>
    // initial хранит исходные вопросы. box — место для карточек в HTML.
    const initial={{ questions|tojson }};const box=document.querySelector('#questions');
    function add(q={text:'',type:'text',required:false,options:[]}){
      // Создаём отдельный блок fieldset и добавляем в него поля вопроса.
      const f=document.createElement('fieldset');
      f.innerHTML='<label>Вопрос<input class="text" required></label><select class="type"><option value="text">Текст</option><option value="single">Один вариант</option><option value="multiple">Несколько вариантов</option></select><label>Варианты — каждый с новой строки<textarea class="options"></textarea></label><label><input type="checkbox" class="required"> Обязательный</label><button type="button" class="up">↑</button> <button type="button" class="remove">Удалить</button>';
      // Переносим значения объекта в поля. join превращает список вариантов
      // в текст, где каждый вариант занимает отдельную строку.
      f.querySelector('.text').value=q.text;f.querySelector('.type').value=q.type;f.querySelector('.options').value=q.options.join('\\n');f.querySelector('.required').checked=q.required;
      // Кнопка удаления убирает карточку, стрелка ставит её перед предыдущей.
      // Порядок блоков на странице затем станет порядком вопросов в JSON.
      f.querySelector('.remove').onclick=()=>f.remove();f.querySelector('.up').onclick=()=>{if(f.previousElementSibling)box.insertBefore(f,f.previousElementSibling)};box.append(f);
    }
    // Сначала показываем все исходные вопросы. Кнопка добавляет пустую карточку.
    initial.forEach(add);document.querySelector('#add').onclick=()=>add();
    // Перед POST читаем каждую карточку. split делит варианты по строкам,
    // trim убирает пробелы по краям, filter убирает пустые строки.
    // JSON.stringify превращает массив объектов в строку для поля questions.
    document.querySelector('#editor').onsubmit=()=>{document.querySelector('#payload').value=JSON.stringify([...box.children].map(f=>({text:f.querySelector('.text').value,type:f.querySelector('.type').value,required:f.querySelector('.required').checked,options:f.querySelector('.options').value.split('\\n').map(x=>x.trim()).filter(Boolean)})))};
    </script>''', questions=questions, survey_title=title, error=error)


# В базе статус хранится как 0 или 1. Выражение 1-published меняет
# 0 на 1 (опубликовать) или 1 на 0 (закрыть), сохраняя адрес опроса.
@app.post('/toggle/<int:survey_id>')
@admin_only
def toggle(survey_id):
    with db() as c:
        c.execute('UPDATE surveys SET published=1-published WHERE id=?', (survey_id,))
    return redirect(url_for('index'))


# Маршрут участника ищет опрос по токену из ссылки. GET показывает форму,
# POST проверяет и сохраняет ответы. Обе операции требуют публикации опроса.
@app.route('/s/<token>', methods=['GET', 'POST'])
def participate(token):
    with db() as c:
        survey = c.execute('SELECT * FROM surveys WHERE token=?', (token,)).fetchone()
    # 404 означает, что опрос с таким токеном не найден.
    # 403 означает, что опрос найден, но сейчас закрыт.
    if not survey:
        abort(404)
    if not survey['published']:
        return page('Опрос закрыт', '<p>Приём ответов сейчас недоступен.</p>'), 403
    questions = json.loads(survey['questions'])
    error = None
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        answers = []
        if not name or len(name) > 200:
            error = 'Укажите имя длиной до 200 символов.'
        # enumerate даёт индекс вопроса, из которого собираем имена полей q0, q1 и так далее.
        # У флажков бывает несколько значений под одним именем, поэтому нужен getlist.
        # Ответ любого типа записываем списком, чтобы формат хранения был одинаковым.
        for i, q in enumerate(questions):
            values = request.form.getlist(f'q{i}') if q['type'] == 'multiple' else [request.form.get(f'q{i}', '').strip()]
            # Убираем пустые значения и повторы с сохранением порядка.
            # Затем проверяем обязательность, длину и принадлежность к списку вариантов.
            values = list(dict.fromkeys(x for x in values if x))
            if (q.get('required') and not values) or any(len(x) > 10000 for x in values):
                error = 'Заполните обязательные вопросы; ответ — до 10000 символов.'
            if q['type'] != 'text' and any(x not in q['options'] for x in values):
                error = 'Выберите ответ из предложенных вариантов.'
            # Даже пропущенный вопрос получает пустой список на своей позиции.
            # Благодаря этому первый список всегда относится к первому вопросу.
            answers.append(values)
        if error is None:
            with db() as c:
                # Сохраняем имя и весь список ответов одной строкой.
                # После POST перенаправление открывает /thanks отдельным GET-запросом.
                c.execute('INSERT INTO answers(survey_id,name,payload) VALUES(?,?,?)', (survey['id'], name, json.dumps(answers, ensure_ascii=False)))
            return redirect(url_for('thanks'))
    # При первом открытии и после ошибки показываем форму одним шаблоном.
    # Он выбирает textarea, radio или checkbox по типу вопроса
    # и подставляет предыдущий ввод из request.form, если отправка не прошла.
    return page(survey['title'], '''<form method="post"><input type="hidden" name="csrf" value="{{ csrf() }}">
    <label>Представьтесь *<input type="text" name="name" required maxlength="200" value="{{ request.form.get('name','') }}"></label>
    {% for q in questions %}{% set n=loop.index0 %}<fieldset><legend>{{ q.text }}{{ ' *' if q.get('required') else '' }}</legend>
    {% if q.type=='text' %}<textarea name="q{{ n }}" maxlength="10000" {{ 'required' if q.get('required') else '' }}>{{ request.form.get('q' ~ n,'') }}</textarea>
    {% else %}{% for option in q.options %}<label><input type="{{ 'radio' if q.type=='single' else 'checkbox' }}" name="q{{ n }}" value="{{ option }}" {{ 'checked' if option in request.form.getlist('q' ~ n) else '' }}> {{ option }}</label>{% endfor %}{% endif %}</fieldset>{% endfor %}<button>Отправить ответы</button></form>''', questions=questions, error=error)


# Отдельная страница подтверждает отправку. Обновление страницы повторит GET.
@app.get('/thanks')
def thanks():
    return page('Спасибо!', '<p>Ваши ответы сохранены.</p>')


# Таблица результатов и экспорт берут данные одинаковым способом.
# Сортируем ответы по ID, чтобы сохранить порядок записей, и декодируем список вопросов.
def get_results(survey_id):
    with db() as c:
        survey = c.execute('SELECT * FROM surveys WHERE id=?', (survey_id,)).fetchone()
        answers = c.execute('SELECT * FROM answers WHERE survey_id=? ORDER BY id', (survey_id,)).fetchall()
    if not survey:
        abort(404)
    return survey, json.loads(survey['questions']), answers


@app.get('/results/<int:survey_id>')
@admin_only
def results(survey_id):
    survey, questions, answers = get_results(survey_id)
    # Каждая строка таблицы показывает имя, дату и значение для каждого вопроса.
    # Если выбранных вариантов несколько, объединяем их в одну ячейку.
    rows = [{'name': a['name'], 'created': a['created'], 'values': ['; '.join(v) for v in json.loads(a['payload'])]} for a in answers]
    # Для каждого варианта считаем ответы, в которых он выбран.
    # Одна анкета может прибавить по единице сразу нескольким вариантам.
    stats = []
    for i, q in enumerate(questions):
        if q['type'] != 'text':
            stats.append((q['text'], [(o, sum(o in json.loads(a['payload'])[i] for a in answers)) for o in q['options']]))
    return page('Результаты: ' + survey['title'], '''<p>Ответов: {{ rows|length }}. Время — UTC.</p><a href="/export/{{ survey_id }}">Скачать CSV</a>
    <div class="scroll"><table><tr><th>Имя</th><th>Дата</th>{% for q in questions %}<th>{{ q.text }}</th>{% endfor %}</tr>{% for row in rows %}<tr><td>{{ row.name }}</td><td>{{ row.created }}</td>{% for v in row['values'] %}<td>{{ v }}</td>{% endfor %}</tr>{% endfor %}</table></div>
    {% for question, counts in stats %}<h2>{{ question }}</h2>{% for option, count in counts %}<p>{{ option }}: {{ count }}</p>{% endfor %}{% endfor %}''', questions=questions, rows=rows, stats=stats, survey_id=survey_id)


@app.get('/export/<int:survey_id>')
@admin_only
def export(survey_id):
    survey, questions, answers = get_results(survey_id)
    # Пишем CSV в память. Модуль csv сам заключает в кавычки поля
    # с разделителем, кавычками и переносами строк.
    output = io.StringIO(newline='')
    writer = csv.writer(output, delimiter=';')
    # Текст, начинающийся с одного из признаков формулы, получает апостроф.
    # Это помогает открывать пользовательские значения как текст в таблицах.
    def safe(value):
        return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) else value
    # Сначала пишем заголовки, затем по строке на анкету.
    # Начальная метка UTF-8 помогает Excel распознать кириллицу.
    # Content-Disposition предлагает браузеру имя скачиваемого файла.
    writer.writerow(['Имя', 'Дата UTC'] + [safe(q['text']) for q in questions])
    for a in answers:
        writer.writerow([safe(a['name']), a['created']] + [safe('; '.join(v)) for v in json.loads(a['payload'])])
    return Response('\ufeff' + output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename=survey-{survey_id}.csv'})


# Этот блок выполняется при запуске python app.py. При импорте модуля,
# например из теста или Waitress, Flask создаётся, но этот сервер не стартует.
# Адрес 127.0.0.1 доступен с того же компьютера.
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=os.environ.get('FLASK_DEBUG') == '1')
