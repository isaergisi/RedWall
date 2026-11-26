import pymysql


class Engine:
    def connect(self):
        return pymysql.connect(host="db")

    def tables(self, db_name):
        sql = "SELECT table_name FROM information_schema.tables WHERE table_schema = %s"  # gt:sink
        cur = self.connect().cursor()
        cur.execute(sql, (db_name,))
        return cur.fetchall()
