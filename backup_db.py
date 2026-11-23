import json
import os
from datetime import datetime
from decimal import Decimal
import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST', '127.0.0.1'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', ''),
        database=os.getenv('DB_NAME', 'cryptovault_db'),
        use_pure=True
    )


def create_verified_backup(backup_type='MANUAL', created_by=None):
    backup_dir = os.getenv('BACKUP_DIR', 'backups')
    os.makedirs(backup_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:19]
    file_name = f'cryptovault_{backup_type.lower()}_{timestamp}.sql'
    sql_path = os.path.join(backup_dir, file_name)
    meta_path = os.path.join(backup_dir, f'{file_name}.meta.json')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT TABLE_NAME
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
            ORDER BY TABLE_NAME
        """)
        tables = [row['TABLE_NAME'] for row in cursor.fetchall()]

        row_counts = {}
        sql_lines = [
            "-- CryptoVault Verified Database Backup",
            f"-- Type: {backup_type}",
            f"-- Generated At: {datetime.now().isoformat()}",
            f"USE `{os.getenv('DB_NAME', 'cryptovault_db')}`;",
            "SET FOREIGN_KEY_CHECKS = 0;\n"
        ]

        for table in tables:
            cursor.execute(f"SHOW CREATE TABLE `{table}`")
            create_stmt = cursor.fetchone()['Create Table']
            sql_lines.append(f"-- Structure for `{table}`")
            sql_lines.append(f"DROP TABLE IF EXISTS `{table}`;")
            sql_lines.append(f"{create_stmt};\n")

            cursor.execute(f"SELECT * FROM `{table}`")
            rows = cursor.fetchall()
            row_counts[table] = len(rows)

            if rows:
                cols = ", ".join(f"`{col}`" for col in rows[0].keys())
                sql_lines.append(f"-- Data for `{table}` ({len(rows)} rows)")
                for r in rows:
                    vals = []
                    for v in r.values():
                        if v is None:
                            vals.append("NULL")
                        elif isinstance(v, (int, float, Decimal)):
                            vals.append(str(v))
                        else:
                            escaped = (
                                str(v)
                                .replace("\\", "\\\\")
                                .replace("'", "\\'")
                                .replace("\r", "\\r")
                                .replace("\n", "\\n")
                            )
                            vals.append(f"'{escaped}'")
                    sql_lines.append(f"INSERT INTO `{table}` ({cols}) VALUES ({', '.join(vals)});")
                sql_lines.append("")

        sql_lines.append("SET FOREIGN_KEY_CHECKS = 1;")
        full_sql = "\n".join(sql_lines)

        with open(sql_path, 'w', encoding='utf-8') as f:
            f.write(full_sql)

        file_size = os.path.getsize(sql_path)
        if file_size < 100 or "SET FOREIGN_KEY_CHECKS = 1;" not in full_sql:
            raise RuntimeError("Backup verification failed: generated SQL snapshot is incomplete.")

        meta = {
            "file_name": file_name,
            "file_path": sql_path,
            "backup_type": backup_type,
            "created_at": datetime.now().isoformat(),
            "file_size_bytes": file_size,
            "tables_backed_up": tables,
            "row_counts": row_counts,
            "verified": True
        }
        with open(meta_path, 'w', encoding='utf-8') as mf:
            json.dump(meta, mf, indent=2)

        if 'db_backups' in tables:
            cursor.execute("""
                INSERT INTO db_backups (file_name, file_path, file_size_bytes, backup_type, created_by)
                VALUES (%s, %s, %s, %s, %s)
            """, (file_name, sql_path, file_size, backup_type, created_by))
            conn.commit()

        return meta
    finally:
        cursor.close()
        conn.close()


def restore_from_backup(sql_path, actor_user_id=None):
    if not os.path.isfile(sql_path):
        raise FileNotFoundError("Selected backup file does not exist on disk.")

    with open(sql_path, 'r', encoding='utf-8') as f:
        sql_content = f.read()

    if "CryptoVault Verified Database Backup" not in sql_content or "SET FOREIGN_KEY_CHECKS = 1;" not in sql_content:
        raise ValueError("Backup file failed integrity header/footer validation.")

    # Never overwrite the only available backup: create a safety snapshot first
    safety_meta = create_verified_backup(backup_type='PRE_RESTORE', created_by=actor_user_id)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        statements = []
        current = []
        in_string = False
        escape_next = False
        for ch in sql_content:
            if escape_next:
                current.append(ch)
                escape_next = False
                continue
            if ch == '\\':
                current.append(ch)
                escape_next = True
                continue
            if ch == "'":
                in_string = not in_string
                current.append(ch)
                continue
            if ch == ';' and not in_string:
                stmt = ''.join(current).strip()
                if stmt and not stmt.startswith('--'):
                    statements.append(stmt)
                current = []
            else:
                current.append(ch)

        for stmt in statements:
            cursor.execute(stmt)
        conn.commit()
        return {"restored_from": sql_path, "pre_restore_backup": safety_meta["file_name"]}
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    result = create_verified_backup('MANUAL')
    print(json.dumps(result, indent=2))