from core.database_manager import DatabaseManager

def main_test():
    db_manager = DatabaseManager()
    print(db_manager.get_host_name_by_address('192.168.62.235'))
    
main_test()