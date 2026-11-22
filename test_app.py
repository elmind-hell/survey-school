import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


# unittest находит методы с именами test_ и выполняет их как отдельные проверки.
# Этот тест проходит весь путь от создания пароля до закрытия опроса.
class SurveyTest(unittest.TestCase):
    def test_full_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            # Загружаем копию приложения: настоящая база ученика не изменяется.
            source = Path(__file__).with_name('app.py').read_text(encoding='utf-8')
            temporary_app = Path(directory) / 'app.py'
            temporary_app.write_text(source, encoding='utf-8')
            # Загружаем временную копию как модуль, чтобы её instance появился
            # рядом с копией. test_client вызывает Flask прямо из Python.
            spec = importlib.util.spec_from_file_location('survey_test_app', temporary_app)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            client = module.app.test_client()
            # Сначала открываем форму. Flask создаёт токен, который понадобится для POST.
            # session_transaction даёт тесту доступ к сессии этого клиента.
            client.get('/login')
            with client.session_transaction() as session:
                token = session['csrf']
            self.assertEqual(client.post('/login', data={'csrf': token, 'password': 'test-password-123'}).status_code, 302)
            # После входа открываем конструктор и берём токен новой сессии.
            # Код 302 означает, что сервер перенаправил клиента после сохранения.
            client.get('/new')
            with client.session_transaction() as session:
                token = session['csrf']
            self.assertEqual(client.post('/new', data={'csrf': token, 'title': 'Тест', 'questions': json.dumps(module.EXAMPLE)}).status_code, 302)
            with module.db() as c:
                survey = c.execute('SELECT * FROM surveys').fetchone()
            # Публикуем опрос. Новый клиент имитирует отдельное окно браузера
            # со своей сессией. Он может отвечать, а результаты требуют входа.
            client.post('/toggle/1', data={'csrf': token})
            visitor = module.app.test_client()
            self.assertEqual(visitor.get('/results/1').status_code, 302)
            # Открываем форму участника, отправляем имя и ответы.
            # q0 и q1 относятся к двум обязательным вопросам стартового набора.
            visitor.get('/s/' + survey['token'])
            with visitor.session_transaction() as session:
                visitor_token = session['csrf']
            self.assertEqual(visitor.post('/s/' + survey['token'], data={'csrf': visitor_token, 'name': 'Анна', 'q0': 'Всё', 'q1': 'Отлично'}).status_code, 302)
            # Проверяем, что имя появляется и в HTML, и в скачиваемом CSV.
            self.assertIn('Анна', client.get('/results/1').get_data(as_text=True))
            self.assertIn('Анна', client.get('/export/1').get_data(as_text=True))
            # Проверяем отказ при отсутствии токена. Затем закрываем опрос
            # правильным запросом и убеждаемся, что форма возвращает 403.
            self.assertEqual(client.post('/toggle/1', data={}).status_code, 400)
            client.post('/toggle/1', data={'csrf': token})
            self.assertEqual(visitor.get('/s/' + survey['token']).status_code, 403)


if __name__ == '__main__':
    unittest.main()
