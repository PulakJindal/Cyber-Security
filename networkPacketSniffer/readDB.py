import sqlite3

conn = sqlite3.connect("packets.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM packets")
rows = cursor.fetchall()

for row in rows:
    print(row)
