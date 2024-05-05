import sqlite3

def set_servfail_domains_to_ok():
    db_path = "stor/cache.db"
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM domains WHERE status = 'SERVFAIL'")
        servfail_domains = cursor.fetchall()

        if servfail_domains:
            updated_domains = [(domain[0], "OK") for domain in servfail_domains]
            cursor.executemany("UPDATE domains SET status=? WHERE domain=?", updated_domains)
            conn.commit()
            print("Updated", len(updated_domains), "domains from SERVFAIL to OK.")
        else:
            print("No domains with SERVFAIL status found.")
    conn.close()

if __name__ == "__main__":
    set_servfail_domains_to_ok()
    
