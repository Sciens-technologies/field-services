from passlib.hash import bcrypt

password = "your_secure_password"  # Replace with your actual password
hashed_password = bcrypt.hash(password)
print(hashed_password)