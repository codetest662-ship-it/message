import psycopg2

conn = psycopg2.connect(
    host="192.168.18.100",
    port=5432,
    dbname="messenger_db",
    user="postgres",
    password="Farhan@12",
)
print("Connected successfully!")
conn.close()