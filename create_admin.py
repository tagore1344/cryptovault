import getpass
import os
import mysql.connector
from argon2 import PasswordHasher
from dotenv import load_dotenv

load_dotenv()
ph = PasswordHasher()


def create_admin():
    full_name = input("Admin Full Name: ").strip()
    email = input("Admin Email Address: ").strip().lower()
    mobile = input("Admin Mobile Number: ").strip()
    password = getpass.getpass("Admin Password (min 8 chars): ")
    confirm = getpass.getpass("Confirm Admin Password: ")

    if not full_name or '@' not in email or len(password) < 8 or password != confirm:
        print("Invalid input or passwords do not match (minimum 8 characters required).")
        return

    pwd_hash = ph.hash(password)
    conn = mysql.connector.connect(
        host=os.getenv('DB_HOST', '127.0.0.1'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', ''),
        database=os.getenv('DB_NAME', 'cryptovault_db'),
        use_pure=True
    )
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        existing = cursor.fetchone()
        if existing:
            cursor.execute("""
                UPDATE users
                SET full_name = %s, mobile_number = %s, password_hash = %s,
                    role = 'ADMIN', account_status = 'ACTIVE', email_verified = 1
                WHERE user_id = %s
            """, (full_name, mobile, pwd_hash, existing['user_id']))
            print(f"Updated existing user {email} to ADMIN.")
        else:
            cursor.execute("""
                INSERT INTO users (full_name, email, mobile_number, password_hash, role, account_status, email_verified)
                VALUES (%s, %s, %s, %s, 'ADMIN', 'ACTIVE', 1)
            """, (full_name, email, mobile, pwd_hash))
            print(f"Created ADMIN account for {email}.")
        conn.commit()
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    create_admin()