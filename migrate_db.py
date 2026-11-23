import os
import mysql.connector
from dotenv import load_dotenv
from backup_db import create_verified_backup

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


def column_exists(cursor, table_name, column_name):
    cursor.execute("""
        SELECT COUNT(*) AS cnt
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
          AND COLUMN_NAME = %s
    """, (table_name, column_name))
    return cursor.fetchone()['cnt'] > 0


def index_exists(cursor, table_name, index_name):
    cursor.execute("""
        SELECT COUNT(*) AS cnt
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
          AND INDEX_NAME = %s
    """, (table_name, index_name))
    return cursor.fetchone()['cnt'] > 0


def run_safe_migrations():
    create_verified_backup('MANUAL')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        user_columns = [
            ("mobile_number", "VARCHAR(20) NULL AFTER email"),
            ("password_hash", "VARCHAR(255) NULL AFTER mobile_number"),
            ("role", "ENUM('USER', 'ADMIN') NOT NULL DEFAULT 'USER' AFTER password_hash"),
            ("account_status", "ENUM('PENDING_VERIFICATION', 'ACTIVE', 'DEACTIVATED', 'SUSPENDED') NOT NULL DEFAULT 'ACTIVE' AFTER role"),
            ("email_verified", "TINYINT(1) NOT NULL DEFAULT 1 AFTER account_status"),
            ("preferred_currency", "ENUM('INR', 'USD') NOT NULL DEFAULT 'INR' AFTER email_verified"),
            ("preferred_language", "ENUM('en', 'hi', 'te') NOT NULL DEFAULT 'en' AFTER preferred_currency"),
            ("theme_mode", "ENUM('light', 'dark') NOT NULL DEFAULT 'light' AFTER preferred_language"),
            ("is_demo", "TINYINT(1) NOT NULL DEFAULT 0 AFTER theme_mode"),
            ("failed_login_attempts", "INT NOT NULL DEFAULT 0 AFTER is_demo"),
            ("locked_until", "DATETIME NULL AFTER failed_login_attempts"),
            ("last_login_at", "DATETIME NULL AFTER locked_until"),
            ("last_login_ip", "VARCHAR(45) NULL AFTER last_login_at")
        ]
        for col_name, col_def in user_columns:
            if not column_exists(cursor, 'users', col_name):
                cursor.execute(f"ALTER TABLE `users` ADD COLUMN `{col_name}` {col_def}")

        crypto_columns = [
            ("coingecko_id", "VARCHAR(60) NULL AFTER name"),
            ("coincap_id", "VARCHAR(60) NULL AFTER coingecko_id"),
            ("market_cap_usd", "DECIMAL(24, 2) DEFAULT 0.00 AFTER change_24h"),
            ("volume_24h_usd", "DECIMAL(24, 2) DEFAULT 0.00 AFTER market_cap_usd"),
            ("is_custom", "TINYINT(1) NOT NULL DEFAULT 0 AFTER color"),
            ("price_source", "VARCHAR(30) NOT NULL DEFAULT 'SEED' AFTER is_custom"),
            ("last_updated", "DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER price_source")
        ]
        for col_name, col_def in crypto_columns:
            if not column_exists(cursor, 'cryptocurrencies', col_name):
                cursor.execute(f"ALTER TABLE `cryptocurrencies` ADD COLUMN `{col_name}` {col_def}")

        coin_mappings = [
            ('BTC', 'bitcoin', 'bitcoin'),
            ('ETH', 'ethereum', 'ethereum'),
            ('SOL', 'solana', 'solana'),
            ('XRP', 'ripple', 'xrp'),
            ('ADA', 'cardano', 'cardano'),
            ('AVAX', 'avalanche-2', 'avalanche'),
            ('LINK', 'chainlink', 'chainlink'),
            ('DOT', 'polkadot', 'polkadot')
        ]
        for sym, cg_id, cc_id in coin_mappings:
            cursor.execute("""
                UPDATE cryptocurrencies
                SET coingecko_id = COALESCE(coingecko_id, %s),
                    coincap_id = COALESCE(coincap_id, %s)
                WHERE symbol = %s
            """, (cg_id, cc_id, sym))

        cursor.execute("""
            ALTER TABLE `transactions`
            MODIFY COLUMN `tx_type` ENUM('BUY', 'SELL', 'DEPOSIT', 'WITHDRAWAL', 'TRANSFER', 'STAKING') NOT NULL
        """)
        if not column_exists(cursor, 'transactions', 'notes'):
            cursor.execute("ALTER TABLE `transactions` ADD COLUMN `notes` VARCHAR(255) NULL AFTER `tx_date`")
        if not column_exists(cursor, 'transactions', 'tx_hash_ref'):
            cursor.execute("ALTER TABLE `transactions` ADD COLUMN `tx_hash_ref` VARCHAR(100) NULL AFTER `notes`")

        if not column_exists(cursor, 'portfolio_holdings', 'avg_buy_price'):
            cursor.execute("ALTER TABLE `portfolio_holdings` ADD COLUMN `avg_buy_price` DECIMAL(18, 8) NOT NULL DEFAULT 0 AFTER `quantity`")
            cursor.execute("""
                UPDATE portfolio_holdings
                SET avg_buy_price = CASE WHEN quantity > 0 THEN total_invested / quantity ELSE 0 END
            """)
        if not column_exists(cursor, 'portfolio_holdings', 'realized_pnl'):
            cursor.execute("ALTER TABLE `portfolio_holdings` ADD COLUMN `realized_pnl` DECIMAL(18, 2) NOT NULL DEFAULT 0.00 AFTER `total_invested`")

        new_tables_sql = [
            """
            CREATE TABLE IF NOT EXISTS `otp_verifications` (
                `otp_id` INT AUTO_INCREMENT PRIMARY KEY,
                `user_id` INT NULL,
                `email` VARCHAR(120) NOT NULL,
                `purpose` ENUM('REGISTER', 'PASSWORD_RESET', 'EMAIL_CHANGE') NOT NULL,
                `otp_hash` VARCHAR(255) NOT NULL,
                `pending_payload` TEXT NULL,
                `expires_at` DATETIME NOT NULL,
                `attempts` INT NOT NULL DEFAULT 0,
                `is_used` TINYINT(1) NOT NULL DEFAULT 0,
                `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX `idx_otp_lookup` (`email`, `purpose`, `is_used`)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS `user_sessions` (
                `session_id` VARCHAR(128) PRIMARY KEY,
                `user_id` INT NOT NULL,
                `ip_address` VARCHAR(45) NULL,
                `user_agent` VARCHAR(255) NULL,
                `remember_me` TINYINT(1) NOT NULL DEFAULT 0,
                `is_active` TINYINT(1) NOT NULL DEFAULT 1,
                `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                `last_seen_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                `expires_at` DATETIME NOT NULL,
                FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS `price_alerts` (
                `alert_id` INT AUTO_INCREMENT PRIMARY KEY,
                `user_id` INT NOT NULL,
                `symbol` VARCHAR(10) NOT NULL,
                `target_price_usd` DECIMAL(18, 8) NOT NULL,
                `direction` ENUM('ABOVE', 'BELOW') NOT NULL,
                `is_triggered` TINYINT(1) NOT NULL DEFAULT 0,
                `triggered_at` DATETIME NULL,
                `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE,
                FOREIGN KEY (`symbol`) REFERENCES `cryptocurrencies`(`symbol`) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS `notifications` (
                `notification_id` INT AUTO_INCREMENT PRIMARY KEY,
                `user_id` INT NOT NULL,
                `category` ENUM('SECURITY', 'PRICE_ALERT', 'TRANSACTION', 'SYSTEM', 'SUPPORT') NOT NULL DEFAULT 'SYSTEM',
                `title` VARCHAR(140) NOT NULL,
                `message` TEXT NOT NULL,
                `is_read` TINYINT(1) NOT NULL DEFAULT 0,
                `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS `support_tickets` (
                `ticket_id` INT AUTO_INCREMENT PRIMARY KEY,
                `user_id` INT NOT NULL,
                `subject` VARCHAR(180) NOT NULL,
                `category` VARCHAR(60) NOT NULL DEFAULT 'General',
                `status` ENUM('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED') NOT NULL DEFAULT 'OPEN',
                `rating` TINYINT NULL,
                `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS `ticket_messages` (
                `message_id` INT AUTO_INCREMENT PRIMARY KEY,
                `ticket_id` INT NOT NULL,
                `sender_id` INT NOT NULL,
                `sender_role` ENUM('USER', 'ADMIN') NOT NULL,
                `body` TEXT NOT NULL,
                `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (`ticket_id`) REFERENCES `support_tickets`(`ticket_id`) ON DELETE CASCADE,
                FOREIGN KEY (`sender_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS `audit_logs` (
                `log_id` INT AUTO_INCREMENT PRIMARY KEY,
                `actor_user_id` INT NULL,
                `target_user_id` INT NULL,
                `event_type` VARCHAR(60) NOT NULL,
                `description` TEXT NOT NULL,
                `ip_address` VARCHAR(45) NULL,
                `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX `idx_audit_actor` (`actor_user_id`),
                INDEX `idx_audit_event` (`event_type`)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS `db_backups` (
                `backup_id` INT AUTO_INCREMENT PRIMARY KEY,
                `file_name` VARCHAR(255) NOT NULL,
                `file_path` VARCHAR(500) NOT NULL,
                `file_size_bytes` BIGINT NOT NULL,
                `backup_type` ENUM('MANUAL', 'AUTOMATIC_DAILY', 'PRE_RESTORE') NOT NULL DEFAULT 'MANUAL',
                `created_by` INT NULL,
                `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS `market_cache` (
                `cache_key` VARCHAR(100) PRIMARY KEY,
                `payload_json` LONGTEXT NOT NULL,
                `source_provider` VARCHAR(40) NOT NULL,
                `fetched_at` DATETIME NOT NULL
            )
            """
        ]
        for ddl in new_tables_sql:
            cursor.execute(ddl)

        if not index_exists(cursor, 'transactions', 'idx_tx_user_date'):
            cursor.execute("CREATE INDEX `idx_tx_user_date` ON `transactions` (`user_id`, `tx_date`)")
        if not index_exists(cursor, 'portfolio_holdings', 'idx_holdings_user'):
            cursor.execute("CREATE INDEX `idx_holdings_user` ON `portfolio_holdings` (`user_id`)")

        cursor.execute("""
            CREATE OR REPLACE VIEW `v_user_portfolio_summary` AS
            SELECT
                h.holding_id,
                h.user_id,
                u.full_name,
                h.symbol,
                c.name AS coin_name,
                h.quantity,
                h.avg_buy_price,
                h.total_invested,
                h.realized_pnl,
                c.current_price AS market_price_usd,
                ROUND(h.quantity * c.current_price, 2) AS current_value_usd,
                ROUND((h.quantity * c.current_price) - h.total_invested, 2) AS unrealized_pnl_usd
            FROM portfolio_holdings h
            JOIN users u ON h.user_id = u.user_id
            JOIN cryptocurrencies c ON h.symbol = c.symbol
            WHERE h.quantity > 0
        """)

        cursor.execute("""
            CREATE OR REPLACE VIEW `v_platform_overview` AS
            SELECT
                (SELECT COUNT(*) FROM users WHERE role = 'USER' AND is_demo = 0) AS total_users,
                (SELECT COUNT(*) FROM users WHERE role = 'USER' AND account_status = 'ACTIVE' AND is_demo = 0) AS active_users,
                (SELECT COUNT(*) FROM transactions) AS total_transactions,
                (SELECT COALESCE(ROUND(SUM(h.quantity * c.current_price), 2), 0)
                 FROM portfolio_holdings h
                 JOIN cryptocurrencies c ON h.symbol = c.symbol
                 JOIN users u ON h.user_id = u.user_id
                 WHERE u.is_demo = 0) AS total_aum_usd
        """)

        cursor.execute("DROP TRIGGER IF EXISTS `after_transaction_insert`")
        cursor.execute("DROP PROCEDURE IF EXISTS `sp_recalculate_holding`")
        cursor.execute("""
            CREATE PROCEDURE `sp_recalculate_holding`(IN p_user_id INT, IN p_symbol VARCHAR(10))
            BEGIN
                DECLARE done INT DEFAULT FALSE;
                DECLARE v_type VARCHAR(20);
                DECLARE v_qty DECIMAL(24, 8);
                DECLARE v_price DECIMAL(24, 8);
                DECLARE v_fee DECIMAL(24, 8);

                DECLARE cur_qty DECIMAL(24, 8) DEFAULT 0;
                DECLARE cur_cost DECIMAL(24, 8) DEFAULT 0;
                DECLARE cur_realized DECIMAL(24, 8) DEFAULT 0;
                DECLARE avg_cost DECIMAL(24, 8) DEFAULT 0;

                DECLARE tx_cursor CURSOR FOR
                    SELECT tx_type, quantity, price_per_coin, fee
                    FROM transactions
                    WHERE user_id = p_user_id AND symbol = p_symbol
                    ORDER BY tx_date ASC, tx_id ASC;

                DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

                OPEN tx_cursor;
                read_loop: LOOP
                    FETCH tx_cursor INTO v_type, v_qty, v_price, v_fee;
                    IF done THEN
                        LEAVE read_loop;
                    END IF;

                    IF v_type = 'BUY' THEN
                        SET cur_cost = cur_cost + (v_qty * v_price) + v_fee;
                        SET cur_qty = cur_qty + v_qty;
                    ELSEIF v_type IN ('DEPOSIT', 'TRANSFER', 'STAKING') THEN
                        SET cur_qty = cur_qty + v_qty;
                    ELSEIF v_type = 'SELL' THEN
                        IF cur_qty > 0 THEN
                            SET avg_cost = cur_cost / cur_qty;
                            SET cur_realized = cur_realized + ((v_qty * v_price) - v_fee - (avg_cost * v_qty));
                            SET cur_cost = GREATEST(0, cur_cost - (avg_cost * v_qty));
                            SET cur_qty = GREATEST(0, cur_qty - v_qty);
                        END IF;
                    ELSEIF v_type = 'WITHDRAWAL' THEN
                        IF cur_qty > 0 THEN
                            SET avg_cost = cur_cost / cur_qty;
                            SET cur_cost = GREATEST(0, cur_cost - (avg_cost * v_qty));
                            SET cur_qty = GREATEST(0, cur_qty - v_qty);
                        END IF;
                    END IF;
                END LOOP;
                CLOSE tx_cursor;

                IF cur_qty > 0.00000001 THEN
                    INSERT INTO portfolio_holdings (user_id, symbol, quantity, avg_buy_price, total_invested, realized_pnl)
                    VALUES (p_user_id, p_symbol, cur_qty, cur_cost / cur_qty, ROUND(cur_cost, 2), ROUND(cur_realized, 2))
                    ON DUPLICATE KEY UPDATE
                        quantity = cur_qty,
                        avg_buy_price = cur_cost / cur_qty,
                        total_invested = ROUND(cur_cost, 2),
                        realized_pnl = ROUND(cur_realized, 2);
                ELSE
                    DELETE FROM portfolio_holdings WHERE user_id = p_user_id AND symbol = p_symbol;
                END IF;
            END
        """)

        conn.commit()
        print("Migration completed successfully. Existing records preserved.")
    except Exception as exc:
        conn.rollback()
        print(f"Migration failed and rolled back: {exc}")
        raise
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    run_safe_migrations()