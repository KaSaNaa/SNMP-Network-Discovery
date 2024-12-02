import sqlite3
from typing import Optional

def get_host_name_by_address(host_address: str, db_path: str = "hosts.db") -> Optional[str]:
    """
    Retrieve the host name associated with a given host address from an SQLite database.

    If the database does not exist, it is created with the necessary schema.

    Parameters:
    host_address (str): The IP address of the host to look up.
    db_path (str): The path to the SQLite database file. Default is "hosts.db".

    Returns:
    Optional[str]:
        - The host name associated with the given host address if found.
        - The host address itself if not found in the database.
        - None if there is an error connecting to the database.

    Example:
    >>> get_host_name_by_address("192.168.1.1")
    'example-hostname'

    >>> get_host_name_by_address("10.0.0.1")
    '10.0.0.1'  # If the host address is not found in the database
    """
    try:
        # Connect to the SQLite database (create if not exists)
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            # Ensure the database has the required table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    host_address TEXT PRIMARY KEY,
                    host_name TEXT
                )
            """)

            # Query to find the host name for the given host address
            query = "SELECT host_name FROM hosts WHERE host_address = ?"
            cursor.execute(query, (host_address,))

            result = cursor.fetchone()

            if result:
                return result[0]  # Return the host name
            else:
                return host_address  # Return the host address if not found

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

if __name__ == "__main__":
    # Example usage
    db_file = "hosts.db"
    test_address = "192.168.1.1"

    result = get_host_name_by_address(test_address, db_file)
    if result:
        print(f"Host name for address {test_address}: {result}")
    else:
        print(f"Failed to retrieve host name for address {test_address}.")