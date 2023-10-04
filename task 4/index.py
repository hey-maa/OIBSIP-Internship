import bcrypt

# Data structure to store user information
users = {}

def register_user(username, password):
    if username in users:
        print("User already exists.")
        return
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = hashed_password
    print("User registered successfully.")

def login_user(username, password):
    if username not in users:
        print("User not found.")
        return False
    stored_password = users[username]
    if bcrypt.checkpw(password.encode('utf-8'), stored_password):
        print("Login successful.")
        return True
    else:
        print("Incorrect password.")
        return False

def secured_page(username):
    print(f"Welcome to the secured page, {username}!")

def main():
    while True:
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            register_user(username, password)

        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            if login_user(username, password):
                secured_page(username)

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()