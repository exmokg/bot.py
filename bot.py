import pymysql
from aiogram import Bot, Dispatcher, types
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton
from aiogram.utils import executor
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.contrib.fsm_storage.memory import MemoryStorage

# 🔹 Данные для подключения к MySQL (InfinityFree)
DB_HOST = "sql312.infinityfree.com"
DB_USER = "if0_36176951"
DB_PASSWORD = "dd41HTdrgi3"
DB_NAME = "if0_36176951_bot"

# 🔹 Токен и ID админа
TOKEN = "8095067567:AAFe08EhwZTh0JKbHvq1mmycRveC9WzlxE4"
ADMIN_ID = 7685258613

bot = Bot(token=TOKEN)
storage = MemoryStorage()
dp = Dispatcher(bot, storage=storage)

# 🔹 Определение состояний для FSM
class BotStates(StatesGroup):
    waiting_for_search = State()
    waiting_for_status_change = State()

# 🔹 Функция подключения к базе
def connect_db():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, cursorclass=pymysql.cursors.DictCursor)

# 🔹 Создание таблицы (если её нет)
def create_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS candidates (
            id INT AUTO_INCREMENT PRIMARY KEY,
            fullName VARCHAR(255),
            age INT,
            address TEXT,
            phone VARCHAR(20),
            telegram VARCHAR(50),
            relocation VARCHAR(10),
            driverLicense VARCHAR(10),
            passport VARCHAR(10),
            status VARCHAR(20) DEFAULT 'Чист',
            date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# 🔹 Меню администратора
admin_menu = ReplyKeyboardMarkup(resize_keyboard=True)
admin_menu.add(
    KeyboardButton("📜 Список кандидатов"),
    KeyboardButton("❌ Список кидков"),
    KeyboardButton("🛠 Изменить вопросы"),
)
admin_menu.add(
    KeyboardButton("✅ Изменить статус кандидата"),
    KeyboardButton("🔍 Поиск кандидата"),
    KeyboardButton("📊 Отчеты"),
)

# 🔹 Команда для входа в админ-меню
@dp.message_handler(commands=["admin_menu"])
async def admin_panel(message: types.Message):
    if message.from_user.id == ADMIN_ID:
        await message.answer("🔹 Меню администратора:", reply_markup=admin_menu)

# 🔹 Поиск кандидата по ФИО
@dp.message_handler(lambda message: message.text == "🔍 Поиск кандидата", state="*")
async def search_candidate_prompt(message: types.Message):
    await BotStates.waiting_for_search.set()
    await message.answer("🔍 Введите ФИО кандидата для поиска:")

@dp.message_handler(state=BotStates.waiting_for_search)
async def search_candidate(message: types.Message, state: FSMContext):
    candidate_name = message.text.strip()
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM candidates WHERE fullName LIKE %s", ("%" + candidate_name + "%",))
    candidate = cursor.fetchone()
    conn.close()
    
    if candidate:
        msg = (
            f"👤 *ФИО:* {candidate['fullName']}\n"
            f"🎂 *Возраст:* {candidate['age']}\n"
            f"🏠 *Адрес:* {candidate['address']}\n"
            f"📞 *Телефон:* {candidate['phone']}\n"
            f"💬 *Telegram:* @{candidate['telegram']}\n"
            f"✈ *Готов к командировке:* {candidate['relocation']}\n"
            f"🚗 *Водительские права:* {candidate['driverLicense']}\n"
            f"🛂 *Загранпаспорт:* {candidate['passport']}\n"
            f"⚠ *Статус:* {candidate['status']}\n"
            f"📅 *Дата добавления:* {candidate['date_added']}"
        )
    else:
        msg = "❌ Кандидат не найден."
    
    await message.answer(msg, parse_mode="Markdown")
    await state.finish()

# 🔹 Получение списка кандидатов за день
@dp.message_handler(lambda message: message.text == "📜 Список кандидатов")
async def list_candidates(message: types.Message):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT fullName, telegram, date_added FROM candidates WHERE date_added >= NOW() - INTERVAL 1 DAY")
    candidates = cursor.fetchall()
    conn.close()
    
    if candidates:
        msg = "\n".join([f"👤 {c['fullName']} | @{c['telegram']} | {c['date_added']}" for c in candidates])
    else:
        msg = "❌ Кандидатов за этот период нет."
    
    await message.answer(msg)

# 🔹 Получение списка "кидков"
@dp.message_handler(lambda message: message.text == "❌ Список кидков")
async def list_kidoks(message: types.Message):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT fullName, telegram, date_added FROM candidates WHERE status = 'Кидок' AND date_added >= NOW() - INTERVAL 1 DAY")
    kidoks = cursor.fetchall()
    conn.close()
    
    if kidoks:
        msg = "\n".join([f"❌ {k['fullName']} | @{k['telegram']} | {k['date_added']}" for k in kidoks])
    else:
        msg = "✅ Кидков за этот период нет."
    
    await message.answer(msg)

# 🔹 Изменение статуса кандидата
@dp.message_handler(lambda message: message.text == "✅ Изменить статус кандидата", state="*")
async def change_status_prompt(message: types.Message):
    await BotStates.waiting_for_status_change.set()
    await message.answer("✏ Введите Telegram кандидата и новый статус ('Кидок' или 'Чист')\nПример: `@username Кидок`", parse_mode="Markdown")

@dp.message_handler(state=BotStates.waiting_for_status_change)
async def change_status(message: types.Message, state: FSMContext):
    parts = message.text.split()
    if len(parts) == 2 and parts[1] in ["Кидок", "Чист"]:
        username = parts[0].replace("@", "")
        new_status = parts[1]
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE candidates SET status = %s WHERE telegram = %s", (new_status, username))
        conn.commit()
        conn.close()
        await message.answer(f"✅ Статус кандидата {username} изменен на {new_status}.")
        await state.finish()
    elif message.text.startswith("@"):
        await message.answer("❌ Неверный формат. Используйте: `@username Кидок` или `@username Чист`")
    else:
        await message.answer("❌ Неверный формат. Используйте: `@username Кидок` или `@username Чист`")
        await state.finish()

# 🔹 Запуск бота
if __name__ == "__main__":
    create_table()
    executor.start_polling(dp, skip_updates=True)
