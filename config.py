SECRET_KEY = ""

HOSTNAME = "127.0.0.1"
PORT = 3306
USERNAME = ""
PASSWORD = ""
DATABASE = "mydatabase"
DB_URI = "".format(USERNAME,PASSWORD,HOSTNAME,PORT,DATABASE)
SQLALCHEMY_DATABASE_URI=DB_URI