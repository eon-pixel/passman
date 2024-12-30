# imports sqlite3 to use database
import sqlite3

# initial database setup
def init_db():
    # connects to the database
    with sqlite3.connect("data") as db:
        cursor = db.cursor()
    # creates tables for master if they don't exist and creates columns
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS master(
            id INTEGER PRIMARY KEY,
            password TEXT NOT NULL);
            """)
    # creates table for vault if it doesn't exist and creates columns
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault(
            id INTEGER PRIMARY KEY,
            platform TEXT NOT NULL,
            userid TEXT NOT NULL,
            password TEXT NOT NULL);
            """)
    # returns connected database and cursor
    return db, cursor
