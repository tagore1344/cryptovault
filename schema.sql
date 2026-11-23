CREATE DATABASE IF NOT EXISTS cryptovault_db;
USE cryptovault_db;

DROP VIEW IF EXISTS v_portfolio_summary;
DROP TABLE IF EXISTS watchlist;
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS portfolio_holdings;
DROP TABLE IF EXISTS cryptocurrencies;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cryptocurrencies (
    symbol VARCHAR(10) PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    current_price DECIMAL(18, 8) NOT NULL CHECK (current_price > 0),
    change_24h DECIMAL(6, 2) DEFAULT 0.00,
    color VARCHAR(20) DEFAULT '#059669'
);

CREATE TABLE portfolio_holdings (
    holding_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    symbol VARCHAR(10) NOT NULL,
    quantity DECIMAL(18, 8) NOT NULL DEFAULT 0 CHECK (quantity >= 0),
    total_invested DECIMAL(18, 2) NOT NULL DEFAULT 0 CHECK (total_invested >= 0),
    UNIQUE KEY unique_user_coin (user_id, symbol),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (symbol) REFERENCES cryptocurrencies(symbol) ON DELETE CASCADE
);

CREATE TABLE transactions (
    tx_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    symbol VARCHAR(10) NOT NULL,
    tx_type ENUM('BUY', 'SELL') NOT NULL,
    quantity DECIMAL(18, 8) NOT NULL CHECK (quantity > 0),
    price_per_coin DECIMAL(18, 8) NOT NULL CHECK (price_per_coin > 0),
    fee DECIMAL(18, 2) NOT NULL DEFAULT 0.00 CHECK (fee >= 0),
    tx_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (symbol) REFERENCES cryptocurrencies(symbol) ON DELETE CASCADE
);

CREATE TABLE watchlist (
    watchlist_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    symbol VARCHAR(10) NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_watch (user_id, symbol),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (symbol) REFERENCES cryptocurrencies(symbol) ON DELETE CASCADE
);

INSERT INTO users (user_id, full_name, email) VALUES
(1, 'Tagore Kolli', 'tagore@cryptovault.local');

INSERT INTO cryptocurrencies (symbol, name, current_price, change_24h, color) VALUES
('BTC', 'Bitcoin', 68420.50, 3.42, '#059669'),
('ETH', 'Ethereum', 3542.80, 2.18, '#6366F1'),
('SOL', 'Solana', 158.24, 5.67, '#0EA5E9'),
('XRP', 'XRP', 0.62400000, -1.23, '#F59E0B'),
('ADA', 'Cardano', 0.48200000, 0.84, '#3B82F6'),
('AVAX', 'Avalanche', 32.84, 4.21, '#E11D48'),
('LINK', 'Chainlink', 18.26, 1.83, '#8B5CF6'),
('DOT', 'Polkadot', 4.12, -0.76, '#EC4899');

INSERT INTO portfolio_holdings (user_id, symbol, quantity, total_invested) VALUES
(1, 'BTC', 0.34000000, 20200.00),
(1, 'ETH', 3.76000000, 11800.00),
(1, 'SOL', 43.20000000, 5900.00),
(1, 'XRP', 4200.00000000, 2700.00),
(1, 'ADA', 6200.00000000, 1580.00);

INSERT INTO transactions (user_id, symbol, tx_type, quantity, price_per_coin, fee, tx_date) VALUES
(1, 'BTC', 'BUY', 0.02500000, 67100.00, 2.50, '2026-11-09 10:42:00'),
(1, 'ETH', 'SELL', 0.18000000, 3610.00, 1.20, '2026-11-08 16:16:00'),
(1, 'SOL', 'BUY', 4.50000000, 149.20, 0.80, '2026-11-07 11:03:00');

INSERT INTO watchlist (user_id, symbol) VALUES
(1, 'AVAX'),
(1, 'LINK'),
(1, 'DOT');

DELIMITER //
CREATE TRIGGER after_transaction_insert
AFTER INSERT ON transactions
FOR EACH ROW
BEGIN
    UPDATE cryptocurrencies
    SET current_price = NEW.price_per_coin
    WHERE symbol = NEW.symbol;

    IF NEW.tx_type = 'BUY' THEN
        INSERT INTO portfolio_holdings (user_id, symbol, quantity, total_invested)
        VALUES (NEW.user_id, NEW.symbol, NEW.quantity, (NEW.quantity * NEW.price_per_coin) + NEW.fee)
        ON DUPLICATE KEY UPDATE
            quantity = quantity + NEW.quantity,
            total_invested = total_invested + (NEW.quantity * NEW.price_per_coin) + NEW.fee;
    ELSEIF NEW.tx_type = 'SELL' THEN
        UPDATE portfolio_holdings
        SET
            total_invested = GREATEST(0, total_invested - (total_invested * (NEW.quantity / quantity))),
            quantity = quantity - NEW.quantity
        WHERE user_id = NEW.user_id AND symbol = NEW.symbol;

        DELETE FROM portfolio_holdings
        WHERE user_id = NEW.user_id AND symbol = NEW.symbol AND quantity <= 0.00000001;
    END IF;
END //
DELIMITER ;