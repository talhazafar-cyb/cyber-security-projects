import sqlite3

conn = sqlite3.connect("database.db")

cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS reports(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type TEXT,
    location TEXT,
    severity TEXT,
    detection_method TEXT,
    description TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()

conn.close()

print("Database Created Successfully")