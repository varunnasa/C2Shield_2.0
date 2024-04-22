import sqlite3

# Connect to the SQLite database (creates a new file if it doesn't exist)
conn = sqlite3.connect('pihole-FTL1.db')
cursor = conn.cursor()

# Create the table 'queries' with the specified fields
cursor.execute('''
    CREATE TABLE IF NOT EXISTS queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        type INTEGER NOT NULL,
        status INTEGER NOT NULL,
        domain TEXT NOT NULL,
        client TEXT NOT NULL,
        forward TEXT,
        additional_info BLOB,
        reply_type INTEGER,
        reply_time REAL,
        dnssec INTEGER
    )
''')

# Define some dummy data to insert into the table
dummy_data = [
    (1713778807, 1, 1, 'example.com', '192.168.1.100', None, None, 3, None, 1),  # Added reply_type 1
    (1713778807, 1, 1, 'google.com', '192.168.1.101', None, None, 3, None, 2),     # Added reply_type 1
    (1713778807, 2, 2, 'openai.com', '192.168.1.102', '8.8.8.8', None, 1, None, 3), # Added reply_type 1
    (1713778807, 2, 2, 'facebook.com', '192.168.1.103', '1.1.1.1', None, 3, None, 4) # Added reply_type 1
]

# Insert the dummy data into the table
cursor.executemany('''
    INSERT INTO queries (timestamp, type, status, domain, client, forward, additional_info, reply_type, reply_time, dnssec)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''', dummy_data)

# Commit changes and close the connection
conn.commit()
conn.close()

print("Database created successfully and dummy entries inserted.")