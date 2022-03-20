from peewee import SqliteDatabase
from peewee import Model
from peewee import IntegerField , PrimaryKeyField, TextField, FloatField , ForeignKeyField

db = SqliteDatabase("hash.sqlite3")

class BaseModel(Model):
    id = PrimaryKeyField()

    class Meta:
        database = db

class File(BaseModel):
    file_path = TextField()

class Packet(BaseModel):
    src_ip = TextField()
    dst_ip = TextField()
    src_port = IntegerField()
    dst_port = IntegerField()
    length = IntegerField()
    stream_id = IntegerField()
    timestamp = FloatField()
    time_delta = FloatField()
    interface_name = TextField(null=True)
    payload = TextField(null=True)
    protocol = TextField()

    query_name = TextField(null=True)
    http_method = TextField(null=True)
    user_agent = TextField(null=True)

    file = ForeignKeyField(File , backref="packets")


db.connect()
db.create_tables([File , Packet])