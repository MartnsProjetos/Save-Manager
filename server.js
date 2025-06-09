// server.js - Servidor Node.js para GestPro OTIMIZADO
// Sistema de Autenticação com MySQL + Redirecionamento

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// =====================================================
// CONFIGURAÇÕES DE SEGURANÇA
// =====================================================

// Configuração do JWT
const JWT_SECRET = process.env.JWT_SECRET || 'gestpro_secret_key_2024';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// Configuração do banco de dados
const DB_CONFIG = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '4529',
    database: process.env.DB_NAME || 'gestpro_db',
    port: process.env.DB_PORT || 3306,
    connectionLimit: 10,
    acquireTimeout: 60000,
    timeout: 60000,
    charset: 'utf8mb4'
};

// Pool de conexões MySQL
let pool;

// Configurações de segurança
const SecurityConfig = {
    password: {
        minLength: 8,
        requireNumbers: true,
        requireSymbols: false,
        requireUppercase: true
    },
    loginAttempts: {
        maxAttempts: 5,
        lockoutTime: 15 * 60 * 1000 // 15 minutos
    },
    bcryptRounds: 12
};

// =====================================================
// MIDDLEWARES
// =====================================================

// Segurança
app.use(helmet({
    contentSecurityPolicy: false // Permitir inline scripts para o frontend
}));

// CORS
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // máximo 100 requests por IP
    message: 'Muitas tentativas, tente novamente em 15 minutos'
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // máximo 5 tentativas de login por IP
    message: 'Muitas tentativas de login, tente novamente em 15 minutos',
    skipSuccessfulRequests: true
});

app.use(limiter);
app.use('/api/auth/login', loginLimiter);

// Parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Arquivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// =====================================================
// UTILITÁRIOS
// =====================================================

const Utils = {
    // Validação de email
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },

    // Validação de senha
    validatePassword(password) {
        const errors = [];
        
        if (password.length < SecurityConfig.password.minLength) {
            errors.push(`Senha deve ter pelo menos ${SecurityConfig.password.minLength} caracteres`);
        }
        
        if (SecurityConfig.password.requireNumbers && !/\d/.test(password)) {
            errors.push('Senha deve conter pelo menos um número');
        }
        
        if (SecurityConfig.password.requireSymbols && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            errors.push('Senha deve conter pelo menos um símbolo especial');
        }
        
        if (SecurityConfig.password.requireUppercase && !/[A-Z]/.test(password)) {
            errors.push('Senha deve conter pelo menos uma letra maiúscula');
        }
        
        return {
            isValid: errors.length === 0,
            errors: errors
        };
    },

    // Sanitizar entrada
    sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        return input.trim().replace(/[<>]/g, '');
    },

    // Obter IP do cliente
    getClientIP(req) {
        return req.ip || 
               req.connection.remoteAddress || 
               req.socket.remoteAddress ||
               (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
               '127.0.0.1';
    }
};

// =====================================================
// CONEXÃO COM BANCO DE DADOS
// =====================================================

async function initDatabase() {
    try {
        console.log('Conectando ao banco MySQL...');
        pool = mysql.createPool(DB_CONFIG);
        
        // Testar conexão
        const connection = await pool.getConnection();
        console.log('✅ Conectado ao MySQL com sucesso!');
        
        // Criar tabelas se não existirem
        await createTables(connection);
        
        connection.release();
        
        // Criar usuário admin padrão
        await createDefaultAdmin();
        
        return true;
    } catch (error) {
        console.error('❌ Erro ao conectar com o banco:', error);
        throw error;
    }
}

async function createTables(connection) {
    const tables = {
        users: `
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role ENUM('admin', 'user', 'manager') DEFAULT 'user',
            profile_image VARCHAR(500) NULL,
            phone VARCHAR(20) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            active BOOLEAN DEFAULT TRUE,
            last_login TIMESTAMP NULL,
            reset_token VARCHAR(255) NULL,
            reset_expires TIMESTAMP NULL,
            email_verified BOOLEAN DEFAULT FALSE,
            verification_token VARCHAR(255) NULL,
            failed_login_attempts INT DEFAULT 0,
            locked_until TIMESTAMP NULL,
            INDEX idx_email (email),
            INDEX idx_active (active)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,
        
        sessions: `
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            session_token VARCHAR(255) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            ip_address VARCHAR(45) NULL,
            user_agent TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_token (session_token),
            INDEX idx_expires (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,
        
        loginLogs: `
        CREATE TABLE IF NOT EXISTS login_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL,
            email VARCHAR(255) NOT NULL,
            success BOOLEAN NOT NULL,
            ip_address VARCHAR(45) NULL,
            user_agent TEXT NULL,
            error_message VARCHAR(500) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_user_id (user_id),
            INDEX idx_success (success),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`
    };

    for (const [tableName, sql] of Object.entries(tables)) {
        try {
            await connection.execute(sql);
            console.log(`✅ Tabela ${tableName} criada/verificada`);
        } catch (error) {
            console.error(`❌ Erro ao criar tabela ${tableName}:`, error);
            throw error;
        }
    }
}

async function createDefaultAdmin() {
    try {
        const [rows] = await pool.execute(
            'SELECT id FROM users WHERE email = ? AND role = ?',
            ['admin@gestpro.com', 'admin']
        );

        if (rows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', SecurityConfig.bcryptRounds);
            
            await pool.execute(`
                INSERT INTO users (name, email, password, role, email_verified) 
                VALUES (?, ?, ?, ?, ?)
            `, ['Administrador', 'admin@gestpro.com', hashedPassword, 'admin', true]);
            
            console.log('✅ Usuário admin padrão criado:');
            console.log('   📧 Email: admin@gestpro.com');
            console.log('   🔑 Senha: admin123');
            console.log('   ⚠️  ALTERE A SENHA APÓS O PRIMEIRO LOGIN!');
        }
    } catch (error) {
        console.error('❌ Erro ao criar admin padrão:', error);
    }
}

// =====================================================
// MIDDLEWARE DE AUTENTICAÇÃO
// =====================================================

async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            error: 'TOKEN_MISSING',
            message: 'Token de acesso requerido' 
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Verificar se usuário ainda existe e está ativo
        const [rows] = await pool.execute(
            'SELECT id, name, email, role, active FROM users WHERE id = ? AND active = TRUE',
            [decoded.userId]
        );

        if (rows.length === 0) {
            return res.status(401).json({ 
                success: false, 
                error: 'USER_NOT_FOUND',
                message: 'Usuário não encontrado ou inativo' 
            });
        }

        req.user = rows[0];
        next();
    } catch (error) {
        return res.status(403).json({ 
            success: false, 
            error: 'INVALID_TOKEN',
            message: 'Token inválido' 
        });
    }
}

// Middleware para verificar role de admin
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            error: 'INSUFFICIENT_PERMISSIONS',
            message: 'Acesso negado - Permissões insuficientes'
        });
    }
    next();
}

// =====================================================
// FUNÇÕES DE BANCO DE DADOS
// =====================================================

const DatabaseService = {
    // Buscar usuário por email
    async findUserByEmail(email) {
        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE email = ? AND active = TRUE',
            [email]
        );
        return rows[0] || null;
    },

    // Buscar usuário por ID
    async findUserById(id) {
        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE id = ? AND active = TRUE',
            [id]
        );
        return rows[0] || null;
    },

    // Criar usuário
    async createUser(userData) {
        const { name, email, password, role = 'user', phone = null } = userData;
        const hashedPassword = await bcrypt.hash(password, SecurityConfig.bcryptRounds);
        
        const [result] = await pool.execute(`
            INSERT INTO users (name, email, password, role, phone) 
            VALUES (?, ?, ?, ?, ?)
        `, [Utils.sanitizeInput(name), email.toLowerCase(), hashedPassword, role, phone]);
        
        return result.insertId;
    },

    // Atualizar último login
    async updateLastLogin(userId) {
        await pool.execute(`
            UPDATE users 
            SET last_login = CURRENT_TIMESTAMP, failed_login_attempts = 0 
            WHERE id = ?
        `, [userId]);
    },

    // Incrementar tentativas falhadas
    async incrementFailedAttempts(email) {
        await pool.execute(`
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE 
                    WHEN failed_login_attempts + 1 >= ? THEN DATE_ADD(NOW(), INTERVAL ? MICROSECOND)
                    ELSE locked_until 
                END
            WHERE email = ?
        `, [SecurityConfig.loginAttempts.maxAttempts, SecurityConfig.loginAttempts.lockoutTime * 1000, email]);
    },

    // Verificar se conta está bloqueada
    async isAccountLocked(email) {
        const [rows] = await pool.execute(
            'SELECT locked_until FROM users WHERE email = ?',
            [email]
        );
        
        if (rows.length === 0) return false;
        
        const lockedUntil = rows[0].locked_until;
        return lockedUntil && new Date(lockedUntil) > new Date();
    },

    // Registrar log de login
    async logLoginAttempt(email, success, userId = null, errorMessage = null, req) {
        await pool.execute(`
            INSERT INTO login_logs (user_id, email, success, ip_address, user_agent, error_message)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [userId, email, success, Utils.getClientIP(req), req.get('User-Agent'), errorMessage]);
    },

    // Listar usuários (admin)
    async getAllUsers() {
        const [rows] = await pool.execute(`
            SELECT id, name, email, role, phone, created_at, updated_at, 
                   active, last_login, failed_login_attempts
            FROM users 
            ORDER BY created_at DESC
        `);
        return rows;
    },

    // Obter estatísticas do sistema
    async getSystemStats() {
        const queries = {
            totalUsers: 'SELECT COUNT(*) as count FROM users',
            activeUsers: 'SELECT COUNT(*) as count FROM users WHERE active = TRUE',
            lockedUsers: 'SELECT COUNT(*) as count FROM users WHERE locked_until > NOW()',
            usersByRole: 'SELECT role, COUNT(*) as count FROM users GROUP BY role',
            loginLast24h: 'SELECT COUNT(*) as count FROM login_logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)',
            successfulLoginLast24h: 'SELECT COUNT(*) as count FROM login_logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR) AND success = TRUE'
        };

        const stats = {};
        
        for (const [key, query] of Object.entries(queries)) {
            const [rows] = await pool.execute(query);
            if (key === 'usersByRole') {
                stats[key] = rows.reduce((acc, row) => {
                    acc[row.role] = row.count;
                    return acc;
                }, {});
            } else {
                stats[key] = rows[0].count;
            }
        }

        return stats;
    }
};

// =====================================================
// ROTAS DE AUTENTICAÇÃO
// =====================================================

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validações básicas
        if (!email || !password) {
            await DatabaseService.logLoginAttempt(email, false, null, 'Dados faltando', req);
            return res.status(400).json({
                success: false,
                error: 'MISSING_DATA',
                message: 'Email e senha são obrigatórios'
            });
        }

        if (!Utils.isValidEmail(email)) {
            await DatabaseService.logLoginAttempt(email, false, null, 'Email inválido', req);
            return res.status(400).json({
                success: false,
                error: 'INVALID_EMAIL',
                message: 'Email inválido'
            });
        }

        // Verificar se conta está bloqueada
        const isLocked = await DatabaseService.isAccountLocked(email);
        if (isLocked) {
            await DatabaseService.logLoginAttempt(email, false, null, 'Conta bloqueada', req);
            return res.status(423).json({
                success: false,
                error: 'ACCOUNT_LOCKED',
                message: 'Conta temporariamente bloqueada devido a múltiplas tentativas de login'
            });
        }

        // Buscar usuário
        const user = await DatabaseService.findUserByEmail(email);
        if (!user) {
            await DatabaseService.incrementFailedAttempts(email);
            await DatabaseService.logLoginAttempt(email, false, null, 'Usuário não encontrado', req);
            return res.status(401).json({
                success: false,
                error: 'INVALID_CREDENTIALS',
                message: 'Email ou senha incorretos'
            });
        }

        // Verificar senha
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            await DatabaseService.incrementFailedAttempts(email);
            await DatabaseService.logLoginAttempt(email, false, user.id, 'Senha incorreta', req);
            return res.status(401).json({
                success: false,
                error: 'INVALID_CREDENTIALS',
                message: 'Email ou senha incorretos'
            });
        }

        // Atualizar último login
        await DatabaseService.updateLastLogin(user.id);

        // Gerar JWT token
        const token = jwt.sign(
            { userId: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        // Log de sucesso
        await DatabaseService.logLoginAttempt(email, true, user.id, null, req);

        // Retornar dados do usuário (sem senha) + URL de redirecionamento
        const { password: _, ...userWithoutPassword } = user;
        
        // URL de redirecionamento sempre para o dashboard
        const redirectUrl = '/dashboard.html';
        
        res.json({
            success: true,
            user: userWithoutPassword,
            token: token,
            redirectUrl: redirectUrl,
            message: 'Login realizado com sucesso'
        });

    } catch (error) {
        console.error('Erro no login:', error);
        await DatabaseService.logLoginAttempt(req.body.email, false, null, 'Erro do servidor', req);
        res.status(500).json({
            success: false,
            error: 'SERVER_ERROR',
            message: 'Erro interno do servidor'
        });
    }
});

// Cadastro
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;

        // Validações básicas
        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                error: 'MISSING_DATA',
                message: 'Nome, email e senha são obrigatórios'
            });
        }

        if (!Utils.isValidEmail(email)) {
            return res.status(400).json({
                success: false,
                error: 'INVALID_EMAIL',
                message: 'Email inválido'
            });
        }

        // Validar senha
        const passwordValidation = Utils.validatePassword(password);
        if (!passwordValidation.isValid) {
            return res.status(400).json({
                success: false,
                error: 'WEAK_PASSWORD',
                message: passwordValidation.errors.join(', ')
            });
        }

        // Verificar se email já existe
        const existingUser = await DatabaseService.findUserByEmail(email);
        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'EMAIL_EXISTS',
                message: 'Email já cadastrado'
            });
        }

        // Criar usuário
        const userId = await DatabaseService.createUser({ name, email, password, phone });
        
        res.status(201).json({
            success: true,
            user: { id: userId, name, email },
            message: 'Usuário cadastrado com sucesso'
        });

    } catch (error) {
        console.error('Erro no cadastro:', error);
        res.status(500).json({
            success: false,
            error: 'SERVER_ERROR',
            message: 'Erro interno do servidor'
        });
    }
});

// Verificar token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({
        success: true,
        user: req.user,
        message: 'Token válido'
    });
});

// Logout (opcional - para blacklist de tokens)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    res.json({
        success: true,
        message: 'Logout realizado com sucesso'
    });
});

// =====================================================
// ROTAS ADMINISTRATIVAS (API)
// =====================================================

// Listar usuários (admin)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await DatabaseService.getAllUsers();
        res.json({
            success: true,
            users: users
        });
    } catch (error) {
        console.error('Erro ao listar usuários:', error);
        res.status(500).json({
            success: false,
            error: 'SERVER_ERROR',
            message: 'Erro interno do servidor'
        });
    }
});

// Estatísticas do sistema (admin)
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const stats = await DatabaseService.getSystemStats();
        res.json({
            success: true,
            stats: stats
        });
    } catch (error) {
        console.error('Erro ao obter estatísticas:', error);
        res.status(500).json({
            success: false,
            error: 'SERVER_ERROR',
            message: 'Erro interno do servidor'
        });
    }
});

// Rota para obter dados do usuário logado (para usar no frontend)
app.get('/api/user/profile', authenticateToken, (req, res) => {
    res.json({
        success: true,
        user: req.user
    });
});

// =====================================================
// ROTAS ESTÁTICAS
// =====================================================

// Página de login (página inicial)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Middleware para capturar todas as rotas não encontradas
// DEVE SER A ÚLTIMA ROTA DEFINIDA
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: 'Rota não encontrada'
    });
});

// =====================================================
// TRATAMENTO DE ERROS
// =====================================================

app.use((error, req, res, next) => {
    console.error('Erro não tratado:', error);
    res.status(500).json({
        success: false,
        error: 'SERVER_ERROR',
        message: 'Erro interno do servidor'
    });
});

// =====================================================
// INICIALIZAÇÃO DO SERVIDOR
// =====================================================

async function startServer() {
    try {
        // Inicializar banco de dados
        await initDatabase();
        
        // Iniciar servidor
        app.listen(PORT, () => {
            console.log(`
🚀 Servidor GestPro iniciado!
🌐 URL: http://localhost:${PORT}
📊 Banco: ${DB_CONFIG.database}@${DB_CONFIG.host}:${DB_CONFIG.port}
🔐 Admin: admin@gestpro.com / admin123
⚠️  ALTERE A SENHA PADRÃO!

📱 Rotas disponíveis:
   🏠 Login: http://localhost:${PORT}/
   📊 Dashboard: http://localhost:${PORT}/dashboard.html
            `);
        });
        
        // Limpeza automática de dados expirados
        setInterval(async () => {
            try {
                await pool.execute(`
                    UPDATE users 
                    SET locked_until = NULL, failed_login_attempts = 0 
                    WHERE locked_until < NOW()
                `);
                
                await pool.execute(`
                    DELETE FROM login_logs 
                    WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
                `);
                
                console.log('🧹 Limpeza automática executada');
            } catch (error) {
                console.error('Erro na limpeza automática:', error);
            }
        }, 60 * 60 * 1000); // A cada hora
        
    } catch (error) {
        console.error('❌ Erro ao iniciar servidor:', error);
        process.exit(1);
    }
}

// Iniciar servidor
startServer();

// Tratamento de shutdown graceful
process.on('SIGINT', async () => {
    console.log('\n🛑 Encerrando servidor...');
    if (pool) {
        await pool.end();
        console.log('📊 Conexões do banco fechadas');
    }
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('\n🛑 Encerrando servidor...');
    if (pool) {
        await pool.end();
        console.log('📊 Conexões do banco fechadas');
    }
    process.exit(0);
});

module.exports = app;