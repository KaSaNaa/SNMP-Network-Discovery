import mysql.connector
from mysql.connector import Error
import os

class DatabaseManager:
    def __init__(self):
        self.db_host = os.getenv('DB_HOST')
        self.db_name = os.getenv('DB_NAME')
        self.db_user = os.getenv('DB_USER')
        self.db_password = os.getenv('DB_PASSWORD')

    def get_host_name_by_address(self, host_address):
        connection = None
        try:
            connection = mysql.connector.connect(
                host=self.db_host,
                database=self.db_name,
                user=self.db_user,
                password=self.db_password
            )
            
            if connection.is_connected():
                print("Connected to MySQL database.")
                cursor = connection.cursor()
                query = "SELECT host_name FROM host WHERE host_address = %s"
                cursor.execute(query, (host_address,))
                result = cursor.fetchone()
                return result[0] if result else host_address
        except Error as e:
            print(f"Error while connecting to MySQL: {e}")
            return None
        finally:
            if connection and connection.is_connected():
                cursor.close()
                connection.close()
                print("MySQL connection closed.")