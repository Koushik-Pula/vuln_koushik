const mariadb = require("mariadb");

const pool = mariadb.createPool({
    host: "localhost", 
    user: "root", 
    database: "app"
});

module.exports = pool;