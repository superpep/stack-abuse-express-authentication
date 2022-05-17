var sqlite3 = require('sqlite3').verbose()
const getHashedPassword = require("./auth.js").getHashedPassword


const DBSOURCE = "db.sqlite"


const db = new sqlite3.Database(DBSOURCE, (err) => {
    if (err) {
      // Cannot open database
      console.error(err.message)
      throw err
    }else{
        console.log('Connected to the SQLite database.')
        db.run(`CREATE TABLE user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name text, 
            email text UNIQUE, 
            password text, 
            role text,
            CONSTRAINT email_unique UNIQUE (email)
            )`,
        (err) => {
            if (err) {
                // Table already created
            }else{
                // Table just created, creating some rows
                var insert = 'INSERT INTO user (name, email, password, role) VALUES (?,?,?,?)'
                db.run(insert, ["admin","admin@example.com",getHashedPassword("admin123456"), 'admin'])
                db.run(insert, ["user","user@example.com",getHashedPassword("user123456"), 'user'])
            }
        });  
    }
});

module.exports = db