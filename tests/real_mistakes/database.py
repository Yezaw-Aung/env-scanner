DB_CONNECTION_STRING = "postgresql://db_admin:admin_P@ssw0rd_987654321@prod-db.cluster.internal:5432/production"
REDIS_URL = "redis://:Redis_Secret_Pass_99887766!_aBcDeFg_12345@redis.prod.internal:6379/0"

def get_connection():
    return DB_CONNECTION_STRING

def get_redis():
    return REDIS_URL