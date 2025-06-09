const mysql = require('mysql2/promise');
require('dotenv').config();

// Criação da pool de conexões
const pool = mysql.createPool({
    host: process.env.DB_HOST,       // Ex: 'localhost' ou endereço do Neon
    user: process.env.DB_USER,       // Ex: 'root'
    password: process.env.DB_PASSWORD, // Senha do banco
    database: process.env.DB_NAME,   // Nome do banco: 'gestpro_db'
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

module.exports = pool;


