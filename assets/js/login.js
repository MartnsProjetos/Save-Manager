// login.js - Integração com MySQL para Store Manager Pro
// Este arquivo deve ser colocado no mesmo diretório do arquivo HTML

// Configurações do banco de dados MySQL
const DB_CONFIG = {
    host: 'localhost',        // ou seu servidor MySQL
    user: 'root',            // usuário do MySQL
    password: 'sua_senha',   // senha do MySQL
    database: 'store_manager', // nome do banco de dados
    port: 3306
};

// Simulação de conexão MySQL (em ambiente real, use Node.js + Express)
// Para ambiente de produção, essas funções devem rodar no backend

/**
 * Autentica usuário no banco de dados MySQL
 * @param {string} email - Email do usuário
 * @param {string} password - Senha do usuário
 * @returns {Object} Resultado da autenticação
 */
async function authenticateUser(email, password) {
    try {
        console.log('🔍 Verificando credenciais no MySQL...');
        console.log('Email:', email);
        
        // Simula delay de consulta ao banco
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        // Em produção, faça a consulta real ao MySQL:
        /*
        const query = `
            SELECT id, name, email, password_hash, created_at, last_login 
            FROM admin_users 
            WHERE email = ? AND active = 1
        `;
        
        const [rows] = await mysql.execute(query, [email]);
        
        if (rows.length === 0) {
            return { success: false, userNotFound: true };
        }
        
        const user = rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        
        if (!passwordMatch) {
            return { success: false, userNotFound: false };
        }
        
        // Atualizar último login
        await mysql.execute(
            'UPDATE admin_users SET last_login = NOW() WHERE id = ?', 
            [user.id]
        );
        
        return {
            success: true,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                lastLogin: user.last_login
            }
        };
        */
        
        // SIMULAÇÃO PARA TESTE (remover em produção)
        const testUsers = [
            {
                id: 1,
                email: 'admin@storemanager.com',
                password: '123456',
                name: 'Administrador Principal',
                created_at: '2024-01-01',
                last_login: new Date().toISOString()
            },
            {
                id: 2,
                email: 'gerente@storemanager.com',
                password: 'gerente123',
                name: 'Gerente da Loja',
                created_at: '2024-01-15',
                last_login: new Date().toISOString()
            },
            {
                id: 3,
                email: 'vendas@storemanager.com',
                password: 'vendas2024',
                name: 'Coordenador de Vendas',
                created_at: '2024-02-01',
                last_login: new Date().toISOString()
            }
        ];
        
        const user = testUsers.find(u => u.email.toLowerCase() === email.toLowerCase());
        
        if (!user) {
            console.log('❌ Usuário não encontrado');
            return { success: false, userNotFound: true };
        }
        
        if (user.password !== password) {
            console.log('❌ Senha incorreta');
            return { success: false, userNotFound: false };
        }
        
        console.log('✅ Login bem-sucedido:', user.name);
        return {
            success: true,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                lastLogin: user.last_login
            }
        };
        
    } catch (error) {
        console.error('❌ Erro na autenticação:', error);
        throw new Error('Erro de conexão com o banco de dados');
    }
}

/**
 * Cria novo usuário no banco de dados
 * @param {string} email - Email do novo usuário
 * @param {string} password - Senha do novo usuário
 * @param {string} name - Nome do novo usuário
 * @returns {Object} Resultado da criação
 */
async function createNewUser(email, password, name) {
    try {
        console.log('👤 Criando novo usuário...');
        console.log('Email:', email);
        console.log('Nome:', name);
        
        // Simula delay de inserção no banco
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Em produção, use o código real do MySQL:
        /*
        // Verificar se email já existe
        const checkQuery = 'SELECT id FROM admin_users WHERE email = ?';
        const [existing] = await mysql.execute(checkQuery, [email]);
        
        if (existing.length > 0) {
            return { success: false, error: 'Email já cadastrado' };
        }
        
        // Hash da senha
        const passwordHash = await bcrypt.hash(password, 12);
        
        // Inserir novo usuário
        const insertQuery = `
            INSERT INTO admin_users (name, email, password_hash, created_at, active) 
            VALUES (?, ?, ?, NOW(), 1)
        `;
        
        const [result] = await mysql.execute(insertQuery, [name, email, passwordHash]);
        
        return {
            success: true,
            userId: result.insertId,
            message: 'Usuário criado com sucesso'
        };
        */
        
        // SIMULAÇÃO PARA TESTE (remover em produção)
        if (email === 'teste@erro.com') {
            return { success: false, error: 'Email já cadastrado no sistema' };
        }
        
        console.log('✅ Usuário criado com sucesso');
        return {
            success: true,
            userId: Math.floor(Math.random() * 1000) + 100,
            message: 'Conta criada com sucesso'
        };
        
    } catch (error) {
        console.error('❌ Erro ao criar usuário:', error);
        return { success: false, error: 'Erro interno do servidor' };
    }
}

/**
 * Estrutura SQL para criar as tabelas necessárias
 */
const CREATE_TABLES_SQL = `
-- Criar banco de dados
CREATE DATABASE IF NOT EXISTS store_manager;
USE store_manager;

-- Tabela de usuários administradores
CREATE TABLE IF NOT EXISTS admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('super_admin', 'admin', 'manager', 'viewer') DEFAULT 'admin',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    profile_image VARCHAR(255) NULL,
    phone VARCHAR(20) NULL,
    department VARCHAR(50) NULL,
    
    INDEX idx_email (email),
    INDEX idx_active (active),
    INDEX idx_role (role)
);

-- Tabela de sessões de login
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    INDEX idx_token (session_token),
    INDEX idx_user_id (user_id),
    INDEX idx_expires (expires_at)
);

-- Tabela de logs de acesso
CREATE TABLE IF NOT EXISTS access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    email VARCHAR(150),
    action ENUM('login_success', 'login_failed', 'logout', 'account_created') NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
);

-- Inserir usuário administrador padrão
INSERT IGNORE INTO admin_users (name, email, password_hash, role) VALUES 
('Administrador Principal', 'admin@storemanager.com', '$2b$12$exemplo_hash_da_senha', 'super_admin');
`;

/**
 * Configuração para ambiente Node.js + Express (backend)
 */
const BACKEND_SETUP_EXAMPLE = `
// Dependências necessárias (npm install)
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// Rate limiting para login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // máximo 5 tentativas por IP
    message: 'Muitas tentativas de login. Tente novamente em 15 minutos.'
});

// Conexão MySQL
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'store_manager',
    port: process.env.DB_PORT || 3306
};

// Rota de autenticação
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Implementar lógica de autenticação aqui
        const result = await authenticateUser(email, password);
        
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro interno' });
    }
});

// Rota para criar usuário
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        
        const result = await createNewUser(email, password, name);
        
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro interno' });
    }
});

app.listen(3000, () => {
    console.log('🚀 Servidor rodando na porta 3000');
});
`;

// Exportar funções para uso no HTML
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        authenticateUser,
        createNewUser,
        CREATE_TABLES_SQL,
        BACKEND_SETUP_EXAMPLE
    };
}

// Logging para debug
console.log('📦 login.js carregado com sucesso!');
console.log('🔧 Configuração MySQL:', { ...DB_CONFIG, password: '***' });
console.log('👥 Usuários de teste disponíveis:');
console.log('   • admin@storemanager.com (senha: 123456)');
console.log('   • gerente@storemanager.com (senha: gerente123)');
console.log('   • vendas@storemanager.com (senha: vendas2024)');