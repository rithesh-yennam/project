-- replace `feedback_db` with your DB name if different
USE feedback_db;

DROP TABLE IF EXISTS feedback;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(150) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('guest','user','admin') DEFAULT 'user',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE feedback (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  message TEXT NOT NULL,
  sentiment VARCHAR(20) NOT NULL,
  score FLOAT NOT NULL,
  pos FLOAT DEFAULT 0,
  neu FLOAT DEFAULT 0,
  neg FLOAT DEFAULT 0,
  product_topic VARCHAR(150),
  rating INT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
ALTER TABLE feedback 
ADD COLUMN feedback_type ENUM('complaint','suggestion','appreciation','bug') NULL AFTER product_topic;
