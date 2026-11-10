use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct Record {
    pub ciphertext: Vec<u8>,
    pub expires_at: i64,
    pub burn: bool,
}

pub enum TakeError {
    Gone,
    Store,
}

enum Backend {
    Memory(Mutex<HashMap<String, Record>>),
    Sqlite(Mutex<Connection>),
}

#[derive(Clone, Copy)]
pub enum Use {
    Created,
    Revealed,
}

#[derive(Clone, Copy, Default)]
struct DayCount {
    creates: i64,
    reveals: i64,
}

pub struct Store {
    backend: Backend,
    counts: Mutex<HashMap<String, DayCount>>,
}

impl Store {
    pub fn memory() -> Self {
        Self {
            backend: Backend::Memory(Mutex::new(HashMap::new())),
            counts: Mutex::new(HashMap::new()),
        }
    }

    pub fn sqlite(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|err| err.to_string())?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|err| err.to_string())?;
        conn.pragma_update(None, "busy_timeout", "5000")
            .map_err(|err| err.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                ciphertext BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                burn INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS secrets_expires ON secrets (expires_at);
            CREATE TABLE IF NOT EXISTS counts (
                day TEXT PRIMARY KEY,
                creates INTEGER NOT NULL,
                reveals INTEGER NOT NULL
            );",
        )
        .map_err(|err| err.to_string())?;
        Ok(Self {
            backend: Backend::Sqlite(Mutex::new(conn)),
            counts: Mutex::new(HashMap::new()),
        })
    }

    /// Add one to today's create or reveal total. The row is the day and the two numbers.
    pub fn record_use(&self, kind: Use) {
        let day = utc_day(now_unix());
        let (creates, reveals) = match kind {
            Use::Created => (1, 0),
            Use::Revealed => (0, 1),
        };
        match &self.backend {
            Backend::Memory(_) => {
                let Ok(mut counts) = self.counts.lock() else {
                    return;
                };
                let row = counts.entry(day).or_default();
                row.creates += creates;
                row.reveals += reveals;
            }
            Backend::Sqlite(conn) => {
                let Ok(conn) = conn.lock() else {
                    return;
                };
                let _ = conn.execute(
                    "INSERT INTO counts (day, creates, reveals) VALUES (?1, ?2, ?3)
                     ON CONFLICT(day) DO UPDATE SET
                       creates = creates + ?2,
                       reveals = reveals + ?3",
                    params![day, creates, reveals],
                );
            }
        }
    }

    pub fn put(&self, id: &str, record: Record) -> Result<(), ()> {
        match &self.backend {
            Backend::Memory(rows) => {
                let mut rows = rows.lock().map_err(|_| ())?;
                rows.insert(id.to_string(), record);
                Ok(())
            }
            Backend::Sqlite(conn) => {
                let conn = conn.lock().map_err(|_| ())?;
                conn.execute(
                    "INSERT INTO secrets (id, ciphertext, expires_at, burn) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        id,
                        record.ciphertext,
                        record.expires_at,
                        if record.burn { 1 } else { 0 }
                    ],
                )
                .map(|_| ())
                .map_err(|_| ())
            }
        }
    }

    /// Return the ciphertext once. A burned secret is deleted in the same step.
    /// An expired secret is deleted and reported as gone.
    pub fn take(&self, id: &str) -> Result<Record, TakeError> {
        let now = now_unix();
        match &self.backend {
            Backend::Memory(rows) => {
                let mut rows = rows.lock().map_err(|_| TakeError::Store)?;
                let Some(record) = rows.get(id) else {
                    return Err(TakeError::Gone);
                };
                if record.expires_at <= now {
                    rows.remove(id);
                    return Err(TakeError::Gone);
                }
                if record.burn {
                    return rows.remove(id).ok_or(TakeError::Gone);
                }
                Ok(record.clone())
            }
            Backend::Sqlite(conn) => {
                let mut conn = conn.lock().map_err(|_| TakeError::Store)?;
                let tx = conn.transaction().map_err(|_| TakeError::Store)?;
                let found = {
                    let mut stmt = tx
                        .prepare("SELECT ciphertext, expires_at, burn FROM secrets WHERE id = ?1")
                        .map_err(|_| TakeError::Store)?;
                    stmt.query_row(params![id], |row| {
                        Ok(Record {
                            ciphertext: row.get(0)?,
                            expires_at: row.get(1)?,
                            burn: row.get::<_, i64>(2)? == 1,
                        })
                    })
                    .optional()
                    .map_err(|_| TakeError::Store)?
                };
                let Some(record) = found else {
                    return Err(TakeError::Gone);
                };
                if record.expires_at <= now || record.burn {
                    tx.execute("DELETE FROM secrets WHERE id = ?1", params![id])
                        .map_err(|_| TakeError::Store)?;
                }
                tx.commit().map_err(|_| TakeError::Store)?;
                if record.expires_at <= now {
                    Err(TakeError::Gone)
                } else {
                    Ok(record)
                }
            }
        }
    }

    pub fn delete_expired(&self) {
        let now = now_unix();
        match &self.backend {
            Backend::Memory(rows) => {
                if let Ok(mut rows) = rows.lock() {
                    rows.retain(|_, record| record.expires_at > now);
                }
            }
            Backend::Sqlite(conn) => {
                if let Ok(conn) = conn.lock() {
                    let _ = conn.execute(
                        "DELETE FROM secrets WHERE expires_at <= ?1",
                        params![now],
                    );
                }
            }
        }
    }
}

pub fn utc_day(unix: i64) -> String {
    let z = unix.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{day:02}")
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(burn: bool, expires_at: i64) -> Record {
        Record {
            ciphertext: b"cipher".to_vec(),
            expires_at,
            burn,
        }
    }

    #[test]
    fn memory_burn_deletes_on_first_take() {
        let store = Store::memory();
        store
            .put("one", sample(true, now_unix() + 60))
            .unwrap();
        assert!(store.take("one").is_ok());
        assert!(matches!(store.take("one"), Err(TakeError::Gone)));
    }

    #[test]
    fn memory_keeps_a_secret_until_it_expires() {
        let store = Store::memory();
        store
            .put("kept", sample(false, now_unix() + 60))
            .unwrap();
        assert!(store.take("kept").is_ok());
        assert!(store.take("kept").is_ok());
    }

    #[test]
    fn memory_drops_an_expired_secret() {
        let store = Store::memory();
        store.put("old", sample(false, now_unix() - 1)).unwrap();
        assert!(matches!(store.take("old"), Err(TakeError::Gone)));
    }

    #[test]
    fn sqlite_burn_deletes_on_first_take() {
        let path = std::env::temp_dir().join(format!("chronolock-test-{}.db", now_unix()));
        let store = Store::sqlite(path.to_str().unwrap()).unwrap();
        store
            .put("one", sample(true, now_unix() + 60))
            .unwrap();
        assert!(store.take("one").is_ok());
        assert!(matches!(store.take("one"), Err(TakeError::Gone)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn utc_day_starts_at_the_epoch() {
        assert_eq!(utc_day(0), "1970-01-01");
        assert_eq!(utc_day(86_400), "1970-01-02");
        assert_eq!(utc_day(1_700_000_000), "2023-11-14");
    }

    #[test]
    fn sqlite_counts_creates_and_reveals_for_the_day() {
        let path = std::env::temp_dir().join(format!("chronolock-counts-{}.db", now_unix()));
        let store = Store::sqlite(path.to_str().unwrap()).unwrap();
        store.record_use(Use::Created);
        store.record_use(Use::Created);
        store.record_use(Use::Revealed);
        let conn = Connection::open(&path).unwrap();
        let (creates, reveals): (i64, i64) = conn
            .query_row(
                "SELECT creates, reveals FROM counts WHERE day = ?1",
                params![utc_day(now_unix())],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((creates, reveals), (2, 1));
        let _ = std::fs::remove_file(&path);
    }
}
