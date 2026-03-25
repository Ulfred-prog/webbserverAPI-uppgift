

CREATE DATABASE IF NOT EXISTS api_db CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE api_db;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO users (username, password) VALUES
  ('user1', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'),  -- password123
  ('user2', '$2a$10$1f.3WV6NCxvs6fP2v4.4XOOdRURN3ybS7YcJswitYn.4zuUmK9qO');         -- secret

SELECT id, username, created_at FROM users;

