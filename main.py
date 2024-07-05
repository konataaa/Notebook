import tkinter
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, ttk, messagebox
from PIL import Image, ImageTk
import binascii
import sqlite3


NUser = ""

# 创建或连接数据库
def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(f"Connected to SQLite database '{db_file}'")
    except sqlite3.Error as e:
        print(f"Error connecting to SQLite database: {e}")
    return conn

# 创建用户表
def create_user_table(conn):
    sql_create_table = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );
    """
    try:
        c = conn.cursor()
        c.execute(sql_create_table)
        print("User table created successfully.")
    except sqlite3.Error as e:
        print(f"Error creating user table: {e}")

# 注册新用户
def register_user(conn, username, password):
    sql_insert_user = """
    INSERT INTO users (username, password)
    VALUES (?, ?);
    """
    try:
        c = conn.cursor()
        c.execute(sql_insert_user, (username, password))
        conn.commit()
        print(f"User '{username}' registered successfully.")
        messagebox.showinfo("Success", "User registered successfully.")
        register_window.withdraw()
        username_entry.delete(0, tkinter.END)
        password_entry.delete(0, tkinter.END)
        login_window.deiconify()

    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists.")
    except sqlite3.Error as e:
        messagebox.showerror("Error", f"Failed to register user: {e}")


#返回登录
def toReg():
    new_username_entry.delete(0, tkinter.END)
    new_password_entry.delete(0, tkinter.END)

    login_window.withdraw()
    register_window.deiconify()


# 验证用户登录
def login_user(conn, username, password):
    sql_select_user = """
    SELECT * FROM users WHERE username=? AND password=?;
    """
    try:
        c = conn.cursor()
        c.execute(sql_select_user, (username, password))
        user = c.fetchone()
        if user:
            global NUser
            NUser = username
            print(f"Login successful: Welcome, {username}!")
            messagebox.showinfo("Success", f"Login successful: Welcome, {username}!")

            return True
        else:
            messagebox.showerror("Error", "Invalid username or password.")
            return False
    except sqlite3.Error as e:
        messagebox.showerror("Error", f"Failed to login: {e}")
        return False



#创件用户记录表
def create_log_table(conn):
    sql_create_table = """
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        file_name TEXT NOT NULL,
        action TEXT NOT NULL
    );
    """
    try:
        c = conn.cursor()
        c.execute(sql_create_table)
        print("Log table created successfully.")
    except sqlite3.Error as e:
        print(f"Error creating log table: {e}")



# 记录用户操作
def log_action(conn, username, action, file_name=""):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    sql_insert_log = """
    INSERT INTO logs (username, timestamp, file_name, action)
    VALUES (?, ?, ?, ?);
    """
    try:
        c = conn.cursor()
        c.execute(sql_insert_log, (username, timestamp, file_name, action))
        conn.commit()
        print(f"Action logged: User '{username}' {action} on {file_name}.")
    except sqlite3.Error as e:
        print(f"Failed to log action: {e}")

#从注册窗口返回登录窗口
def Back():
    username_entry.delete(0,tkinter.END)
    password_entry.delete(0, tkinter.END)
    register_window.withdraw()
    login_window.deiconify()

# 打开文件处理函数
def open_file():
    file_name = filedialog.askopenfilename(
        title="Open File",
        filetypes=(("All Files", "*.*"),
                   ("Binary Files", "*.bin"),
                   ("ASCII Files", "*.txt"),
                   ("Image Files", "*.png;*.jpg;*.bmp"))
    )
    if file_name:
        handle_file(file_name)
        log_action(create_connection("file_editor.db"), NUser, "open", file_name)

# 处理文件类型
def handle_file(file_name):
    if file_name.endswith(('.png', '.jpg', '.bmp')):
        display_image(file_name)
    elif file_name.endswith('.txt'):
        display_ascii(file_name)
    else:
        display_binary(file_name)

# 显示图像文件
def display_image(file_name):
    image = Image.open(file_name)
    max_size = (root.winfo_width()-100, root.winfo_height()-100)
    image.thumbnail(max_size, Image.LANCZOS)
    photo = ImageTk.PhotoImage(image)
    open_new_window(photo, is_image=True, file_name=file_name)

# 显示文本文件
def display_ascii(file_name):
    with open(file_name, 'r', encoding='utf-8') as file:
        content = file.read()
    open_new_window(content, is_image=False, file_name=file_name)

# 显示二进制文件
def display_binary(file_name):
    with open(file_name, 'rb') as file:
        content = file.read()
    hex_content = binascii.hexlify(content).decode('utf-8')
    open_new_window(hex_content, is_image=False, file_name=file_name)

# 打开新窗口并显示内容
def open_new_window(content, is_image=False, file_name=""):
    new_frame = ttk.Frame(notebook)
    notebook.add(new_frame, text=file_name.split('/')[-1])

    if is_image:
        label = tk.Label(new_frame, image=content)
        label.image = content
        label.pack(fill=tk.BOTH, expand=True)
    else:
        text_area = tk.Text(new_frame)
        scrollbar = ttk.Scrollbar(text_area, orient=tk.VERTICAL, command=text_area.yview)
        text_area.configure(yscrollcommand=scrollbar.set)
        # text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_area.insert(tk.END, content)
        text_area.pack(fill=tk.BOTH, expand=True)
        text_area.file_path = file_name
        #在非图片文件中添加一个保存按钮
        save_button = ttk.Button(new_frame, text="Save", command=save_file)
        save_button.pack(side=tk.LEFT, padx=5, pady=5)
        #添加一个编辑按钮
        edit_button = ttk.Button(new_frame, text="edit", command=edit_file)
        edit_button.pack(side=tk.LEFT, padx=5, pady=5)
        text_area.config(state=tk.DISABLED)

    # 添加一个关闭按钮
    close_button = ttk.Button(new_frame, text="Close", command=lambda: close_window(new_frame))
    close_button.pack(side=tk.RIGHT, padx=5, pady=5)

    #跳转到现在页面
    notebook.select(new_frame)

# 关闭窗口
def close_window(frame):
    notebook.forget(frame)

# 保存文件
def save_file():
    current_tab = notebook.select()
    if current_tab:
        current_frame = notebook.nametowidget(current_tab)
        text_area = current_frame.winfo_children()[0]
        if hasattr(text_area, 'file_path') and text_area.file_path:
            file_path = text_area.file_path
        else:
            file_path = filedialog.asksaveasfilename(
                title="Save File",
                filetypes=(("All Files", "*.*"), ("Text Files", "*.txt"))
            )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(text_area.get("1.0", tk.END))
                messagebox.showinfo("Success", "File saved successfully.")
                log_action(create_connection("file_editor.db"),NUser,"save",file_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")
        text_area.config(state=tk.DISABLED)

#编辑文件
def edit_file():
    current_tab = notebook.select()
    if current_tab:
        current_frame = notebook.nametowidget(current_tab)
        text_area = current_frame.winfo_children()[0]
        text_area.config(state=tk.NORMAL)


# 创建菜单
def create_menu():
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    file_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="File", menu=file_menu)

    file_menu.add_command(label="Open", command=open_file)
    # file_menu.add_command(label="Save", command=save_file)
    file_menu.add_command(label="Close Current Tab", command=lambda: close_window(notebook.select()))
    file_menu.add_command(label="Show History", command=show_history)
    file_menu.add_separator()
    file_menu.add_command(label="Login_Exit", command=login_out)
    file_menu.add_command(label="Exit", command=root.quit)

    """
    window_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Window", menu=window_menu)
    window_menu.add_command(label="Close Current Tab", command=lambda: close_window(notebook.select()))
    """

# 登录验证函数
def login():
    username = username_entry.get()
    password = password_entry.get()
    if login_user(conn, username, password):
        login_window.withdraw()
        root.deiconify()  # 显示主窗口
        password_entry.delete(0, tk.END)
    else:
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)

# 注册新用户函数
def register():
    new_username = new_username_entry.get()
    new_password = new_password_entry.get()
    register_user(conn, new_username, new_password)

# 主窗口打开第一个文件函数
def open_first_file(event):
    if not notebook.tabs():
        open_file()


def login_out():
    root.withdraw()
    login_window.deiconify()


def show_history():
    history_window = tk.Toplevel(root)
    history_window.title("User Action History")
    history_window.geometry("700x500")

    # 创建文本框
    history_text = tk.Text(history_window, wrap=tk.WORD)
    history_text.pack(expand=True, fill=tk.BOTH)

    # 创建滚动条
    scrollbar = tk.Scrollbar(history_text)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    # 配置滚动条
    history_text.configure(yscrollcommand=scrollbar.set)
    scrollbar.config(command=history_text.yview)


    #创建清空历史记录按钮
    history_clear_button = ttk.Button(history_window, text="clear", command=lambda: history_clear(history_window))
    history_clear_button.pack(side=tk.RIGHT, padx=5, pady=5)

    # 从数据库中读取历史记录并显示
    sql_select_logs = """
    SELECT timestamp, username, action, file_name FROM logs ORDER BY timestamp DESC;
    """
    try:
        c = conn.cursor()
        c.execute(sql_select_logs)
        logs = c.fetchall()
        for log in logs:
            history_text.insert(tk.END, f"{log[0]} - {log[1]} - {log[2]} - {log[3]}\n")

        history_text.config(state=tk.DISABLED)
    except sqlite3.Error as e:
        messagebox.showerror("Error", f"Failed to retrieve logs: {e}")

#清空历史记录
def history_clear(history_window):
    sql_delete_logs = """
        DELETE FROM logs;
        """
    try:
        c = conn.cursor()
        c.execute(sql_delete_logs)
        conn.commit()
        history_window.destroy()
        show_history()
    except sqlite3.Error as e:
        messagebox.showerror("Error", f"Failed to retrieve logs: {e}")



# 主程序
if __name__ == "__main__":
    db_file = "file_editor.db"  # SQLite数据库文件名
    conn = create_connection(db_file)
    if conn is not None:
        create_user_table(conn)  # 创建用户表
        create_log_table(conn)   # 如果需要，创建操作记录表
    else:
        print("Error: Unable to connect to database.")

    #创建主窗口
    root = tk.Tk()
    root.title("File Editor")

    # 创建样式对象
    style = ttk.Style()
    style.theme_use('clam')

    # 自定义样式
    # style.configure('TButton', background='#4CAF50', foreground='white', font=('Arial', 12, 'bold'))
    style.configure('TLabel', font=('Arial', 12))
    # style.configure('TNotebook.Tab', background='#f0f0f0', padding=5)

    # 修改按钮样式为圆角并设置大小
    style.layout('Custom.TButton', [
        ('Button.button', {'children': [('Button.focus', {'children': [('Button.padding', {
            'children': [('Button.label', {'sticky': 'nswe'})],
            'sticky': 'nswe',
            'border': '10',
        })],
        'sticky': 'nswe'})],
        'sticky': 'nswe'})])

    style.configure('Custom.TButton', width=10, height=20, borderwidth=0, relief='flat')



    # 设置窗口大小和位置
    window_width = 800
    window_height = 600

    # 获取屏幕宽度和高度
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # 计算窗口左上角位置，使其在屏幕中央
    x_offset = (screen_width - window_width) // 2
    y_offset = (screen_height - window_height) // 2

    # 设置窗口的大小和位置
    root.geometry(f"{window_width}x{window_height}+{x_offset}+{y_offset}")
    root.withdraw()  # 隐藏主窗口，直到登录成功

    # 登录窗口
    login_window = tk.Toplevel(root)
    login_window.title("Login")
    login_window_width = 400
    login_window_height = 300
    login_x_offset = (screen_width - login_window_width) // 2
    login_y_offset = (screen_height - login_window_height) // 2
    login_window.geometry(f"{login_window_width}x{login_window_height}+{login_x_offset}+{login_y_offset}")

    # login_window.geometry("700x550")

    username_label = tk.Label(login_window, text="Username:")
    username_label.grid(row=0, column=0, sticky=tk.W, padx=(90, 10), pady=(50, 20))  # 添加右侧填充
    # username_label.pack(pady=5)
    username_entry = ttk.Entry(login_window)
    username_entry.grid(row=0, column=1, sticky=tk.E, pady=(50, 20))
    # username_entry.pack(pady=5)

    password_label = tk.Label(login_window, text="Password:")
    password_label.grid(row=1, column=0, sticky=tk.W, padx=(90, 10))
    # password_label.pack(pady=5)
    password_entry = ttk.Entry(login_window, show="*")
    password_entry.grid(row=1, column=1, sticky=tk.E)
    # password_entry.pack(pady=5)

    login_button = ttk.Button(login_window, text="Login", command=login, style='Custom.TButton')
    login_button.grid(row=2, columnspan=2, pady=(20, 0), padx=(100, 0))
    # login_button.pack(pady=5)

    Reg_button = ttk.Button(login_window, text="Register", command=toReg, style='Custom.TButton')
    Reg_button.grid(row=3, columnspan=2, pady=(10, 0), padx=(100, 0))
    # login_button.pack(pady=5)



    # 注册窗口
    register_window = tk.Toplevel(root)
    register_window.title("Register")
    register_window_width = 400
    register_window_height = 300
    register_x_offset = (screen_width - register_window_width) // 2
    register_y_offset = (screen_height - register_window_height) // 2
    register_window.geometry(f"{register_window_width}x{register_window_height}+{register_x_offset}+{register_y_offset}")

    # register_window.geometry("300x150")

    new_username_label = tk.Label(register_window, text="New Username:")
    new_username_label.grid(row=0, column=0, sticky=tk.W, padx=(70, 10), pady=(50, 20))  # 添加右侧填充
    # new_username_label.pack(pady=5)
    new_username_entry = ttk.Entry(register_window)
    new_username_entry.grid(row=0, column=1, sticky=tk.E, pady=(50, 20))
    # new_username_entry.pack(pady=5)

    new_password_label = tk.Label(register_window, text="New Password:")
    new_password_label.grid(row=1, column=0, sticky=tk.W, padx=(70, 10))
    # new_password_label.pack(pady=5)
    new_password_entry = ttk.Entry(register_window, show="*")
    new_password_entry.grid(row=1, column=1, sticky=tk.E)
    # new_password_entry.pack(pady=5)

    register_button = ttk.Button(register_window, text="Register", command=register, style='Custom.TButton')
    register_button.grid(row=2, columnspan=2, pady=(20, 0), padx=(100, 0))
    # register_button.pack(pady=5)
    back_button = ttk.Button(register_window, text="Back", command=Back, style='Custom.TButton')
    back_button.grid(row=3, columnspan=2, pady=(10, 0), padx=(100, 0))
    # register_button.pack(pady=5)
    register_window.withdraw()
    # 主窗口和菜单


    create_menu()

    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    root.bind("<Button-1>", open_first_file)

    root.mainloop()

    # 关闭数据库连接
    if conn:
        conn.close()
