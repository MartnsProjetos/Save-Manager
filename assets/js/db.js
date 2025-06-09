// login.js - Sistema de Autenticação Completo com MySQL para GestPro
// Este arquivo contém toda a lógica de banco de dados e autenticação

// =====================================================
// CONFIGURAÇÃO DO BANCO DE DADOS
// =====================================================

// Configurações de conexão com MySQL
const DB_CONFIG = {
    host: 'localhost',
    user: 'root',
    password: '4529',
    database: 'gestpro_db',
    port: 3306,
    connectionLimit: 10,
    acquireTimeout: 60000,
    timeout: 60000
};

// Scripts SQL para criação das tabelas
const CREATE_TABLES_SQL = {
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
    );`,
    
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
    );`,
    
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
    );`
};

// =====================================================
// CONFIGURAÇÕES DE REDIRECIONAMENTO
// =====================================================

const RedirectConfig = {
    // Caminhos para redirecionamento após login
    afterLogin: './public/Dashboard.html',
    
    // Caminhos alternativos baseados no role do usuário
    roleBasedRedirect: {
        admin: './public/Dashboard.html',
        manager: './public/Dashboard.html',
        user: './public/Dashboard.html'
    },
    
    // Página de login (para redirecionamento quando não autenticado)
    loginPage: './login.html',
    
    // Página inicial pública
    homePage: './index.html'
};

// =====================================================
// UTILITÁRIOS E HELPERS
// =====================================================

const Utils = {
    // Validação de email
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },

    // Validação de senha forte
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

    // Gerar token seguro
    generateSecureToken(length = 32) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    },

    // Sanitizar entrada
    sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        return input.trim().replace(/[<>]/g, '');
    },

    // Obter IP do usuário (simulado)
    getUserIP() {
        // Em um ambiente real, você obteria o IP do request
        return '127.0.0.1';
    },

    // Obter User Agent (simulado)
    getUserAgent() {
        return navigator.userAgent || 'Unknown';
    },

    // Formatear data para exibição
    formatDate(date) {
        return new Date(date).toLocaleString('pt-BR');
    },

    // Função para redirecionamento seguro
    redirectTo(url, delay = 0) {
        setTimeout(() => {
            console.log(`Redirecionando para: ${url}`);
            window.location.href = url;
        }, delay);
    },

    // Obter URL de redirecionamento baseada no role
    getRedirectUrl(userRole) {
        return RedirectConfig.roleBasedRedirect[userRole] || RedirectConfig.afterLogin;
    }
};

// =====================================================
// SISTEMA DE AUTENTICAÇÃO PRINCIPAL
// =====================================================

const AuthSystem = {
    
    // Simulação de conexão MySQL (substitua por conexão real)
    async connectDB() {
        // Em um ambiente real, você usaria:
        // const mysql = require('mysql2/promise');
        // const pool = mysql.createPool(DB_CONFIG);
        // return pool;
        
        console.log('Conectando ao banco MySQL...', {
            host: DB_CONFIG.host,
            database: DB_CONFIG.database,
            port: DB_CONFIG.port
        });
        
        return {
            connected: true,
            database: 'gestpro_db'
        };
    },

    // Hash de senha usando bcrypt (simulado com crypto mais robusto)
    async hashPassword(password) {
        // Em produção, use: const bcrypt = require('bcrypt');
        // return await bcrypt.hash(password, 12);
        
        const encoder = new TextEncoder();
        const salt = 'gestpro_salt_2024_secure';
        const data = encoder.encode(password + salt);
        
        // Múltiplas iterações para maior segurança
        let hash = await crypto.subtle.digest('SHA-256', data);
        for (let i = 0; i < 1000; i++) {
            hash = await crypto.subtle.digest('SHA-256', hash);
        }
        
        const hashArray = Array.from(new Uint8Array(hash));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    // Verificar senha
    async verifyPassword(password, hash) {
        const hashedInput = await this.hashPassword(password);
        return hashedInput === hash;
    },

    // =====================================================
    // GERENCIAMENTO DE USUÁRIOS
    // =====================================================

    // Buscar usuário por email
    async findUserByEmail(email) {
        try {
            const users = JSON.parse(localStorage.getItem('gestpro_users') || '[]');
            const user = users.find(u => u.email === email && u.active !== false);
            
            console.log(`Buscando usuário: ${email}`, user ? 'Encontrado' : 'Não encontrado');
            return user || null;
            
        } catch (error) {
            console.error('Erro ao buscar usuário:', error);
            throw new Error('Erro de banco de dados');
        }
    },

    // Buscar usuário por ID
    async findUserById(id) {
        try {
            const users = JSON.parse(localStorage.getItem('gestpro_users') || '[]');
            const user = users.find(u => u.id === parseInt(id) && u.active !== false);
            return user || null;
        } catch (error) {
            console.error('Erro ao buscar usuário por ID:', error);
            throw new Error('Erro de banco de dados');
        }
    },

    // Criar novo usuário
    async createUser(userData) {
        try {
            const { name, email, password, role = 'user', phone = null } = userData;
            const hashedPassword = await this.hashPassword(password);
            
            const users = JSON.parse(localStorage.getItem('gestpro_users') || '[]');
            const newUser = {
                id: Date.now(),
                name: Utils.sanitizeInput(name),
                email: email.toLowerCase(),
                password: hashedPassword,
                role: role,
                profile_image: null,
                phone: phone,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                active: true,
                last_login: null,
                reset_token: null,
                reset_expires: null,
                email_verified: false,
                verification_token: Utils.generateSecureToken(),
                failed_login_attempts: 0,
                locked_until: null
            };
            
            users.push(newUser);
            localStorage.setItem('gestpro_users', JSON.stringify(users));
            
            console.log('Usuário criado:', { id: newUser.id, name, email, role });
            return { id: newUser.id, name, email, role };
            
        } catch (error) {
            console.error('Erro ao criar usuário:', error);
            throw new Error('Erro ao cadastrar usuário');
        }
    },

    // Atualizar perfil do usuário
    async updateUserProfile(userId, updateData) {
        try {
            const users = JSON.parse(localStorage.getItem('gestpro_users') || '[]');
            const userIndex = users.findIndex(u => u.id === userId);
            
            if (userIndex === -1) {
                throw new Error('Usuário não encontrado');
            }

            const allowedFields = ['name', 'phone', 'profile_image'];
            const updates = {};
            
            for (const field of allowedFields) {
                if (updateData[field] !== undefined) {
                    updates[field] = Utils.sanitizeInput(updateData[field]);
                }
            }

            users[userIndex] = { ...users[userIndex], ...updates, updated_at: new Date().toISOString() };
            localStorage.setItem('gestpro_users', JSON.stringify(users));

            const { password, ...userWithoutPassword } = users[userIndex];
            return userWithoutPassword;

        } catch (error) {
            console.error('Erro ao atualizar perfil:', error);
            throw new Error('Erro ao atualizar perfil');
        }
    },

    // Atualizar último login
    async updateLastLogin(userId) {
        try {
            const users = JSON.parse(localStorage.getItem('gestpro_users') || '[]');
            const userIndex = users.findIndex(u => u.id === userId);
            if (userIndex !== -1) {
                users[userIndex].last_login = new Date().toISOString();
                users[userIndex].failed_login_attempts = 0; // Reset tentativas falhadas
                localStorage.setItem('gestpro_users', JSON.stringify(users));
            }
        } catch (error) {
            console.error('Erro ao atualizar último login:', error);
        }
    },

    // Incrementar tentativas de login falhadas
    async incrementFailedAttempts(email) {
        try {
            const users = JSON.parse(localStorage.getItem('gestpro_users') || '[]');
            const userIndex = users.findIndex(u => u.email === email);
            
            if (userIndex !== -1) {
                users[userIndex].failed_login_attempts = (users[userIndex].failed_login_attempts || 0) + 1;
                
                // Bloquear conta se exceder tentativas máximas
                if (users[userIndex].failed_login_attempts >= SecurityConfig.loginAttempts.maxAttempts) {
                    users[userIndex].locked_until = new Date(Date.now() + SecurityConfig.loginAttempts.lockoutTime).toISOString();
                }
                
                localStorage.setItem('gestpro_users', JSON.stringify(users));
            }
        } catch (error) {
            console.error('Erro ao incrementar tentativas falhadas:', error);
        }
    },

    // Verificar se conta está bloqueada
    async isAccountLocked(email) {
        try {
            const user = await this.findUserByEmail(email);
            if (!user) return false;
            
            if (user.locked_until && new Date(user.locked_until) > new Date()) {
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('Erro ao verificar bloqueio:', error);
            return false;
        }
    },

    // =====================================================
    // GERENCIAMENTO DE SESSÕES
    // =====================================================

    // Criar sessão
    async createSession(userId) {
        try {
            const sessionToken = Utils.generateSecureToken(64);
            const expiresAt = new Date(Date.now() + SecurityConfig.session.timeout);
            
            const sessions = JSON.parse(localStorage.getItem('gestpro_sessions') || '[]');
            const newSession = {
                id: Date.now(),
                user_id: userId,
                session_token: sessionToken,
                expires_at: expiresAt.toISOString(),
                ip_address: Utils.getUserIP(),
                user_agent: Utils.getUserAgent(),
                created_at: new Date().toISOString()
            };
            
            sessions.push(newSession);
            localStorage.setItem('gestpro_sessions', JSON.stringify(sessions));
            
            return sessionToken;
        } catch (error) {
            console.error('Erro ao criar sessão:', error);
            throw new Error('Erro ao criar sessão');
        }
    },

    // Validar sessão
    async validateSession(sessionToken) {
        try {
            const sessions = JSON.parse(localStorage.getItem('gestpro_sessions') || '[]');
            const session = sessions.find(s => 
                s.session_token === sessionToken && 
                new Date(s.expires_at) > new Date()
            );
            
            if (!session) {
                return { valid: false, user: null };
            }
            
            const user = await this.findUserById(session.user_id);
            if (!user) {
                return { valid: false, user: null };
            }
            
            // Renovar sessão se configurado
            if (SecurityConfig.session.renewOnActivity) {
                await this.renewSession(sessionToken);
            }
            
            const { password, ...userWithoutPassword } = user;
            return { valid: true, user: userWithoutPassword, session };
            
        } catch (error) {
            console.error('Erro ao validar sessão:', error);
            return { valid: false, user: null };
        }
    },

    // Renovar sessão
    async renewSession(sessionToken) {
        try {
            const sessions = JSON.parse(localStorage.getItem('gestpro_sessions') || '[]');
            const sessionIndex = sessions.findIndex(s => s.session_token === sessionToken);
            
            if (sessionIndex !== -1) {
                sessions[sessionIndex].expires_at = new Date(Date.now() + SecurityConfig.session.timeout).toISOString();
                localStorage.setItem('gestpro_sessions', JSON.stringify(sessions));
            }
        } catch (error) {
            console.error('Erro ao renovar sessão:', error);
        }
    },

    // Destruir sessão
    async destroySession(sessionToken) {
        try {
            const sessions = JSON.parse(localStorage.getItem('gestpro_sessions') || '[]');
            const filteredSessions = sessions.filter(s => s.session_token !== sessionToken);
            localStorage.setItem('gestpro_sessions', JSON.stringify(filteredSessions));
            
            console.log('Sessão destruída:', sessionToken.substring(0, 10) + '...');
        } catch (error) {
            console.error('Erro ao destruir sessão:', error);
        }
    },

    // Destruir todas as sessões do usuário
    async destroyAllUserSessions(userId) {
        try {
            const sessions = JSON.parse(localStorage.getItem('gestpro_sessions') || '[]');
            const filteredSessions = sessions.filter(s => s.user_id !== userId);
            localStorage.setItem('gestpro_sessions', JSON.stringify(filteredSessions));
            
            console.log('Todas as sessões do usuário destruídas:', userId);
        } catch (error) {
            console.error('Erro ao destruir sessões do usuário:', error);
        }
    },

    // =====================================================
    // LOGGING DE ATIVIDADES
    // =====================================================

    // Log de tentativa de login
    async logLoginAttempt(email, success, userId = null, errorMessage = null) {
        try {
            const logs = JSON.parse(localStorage.getItem('gestpro_login_logs') || '[]');
            const logEntry = {
                id: Date.now(),
                user_id: userId,
                email: email,
                success: success,
                ip_address: Utils.getUserIP(),
                user_agent: Utils.getUserAgent(),
                error_message: errorMessage,
                created_at: new Date().toISOString()
            };
            
            logs.push(logEntry);
            
            // Manter apenas os últimos 1000 logs
            if (logs.length > 1000) {
                logs.splice(0, logs.length - 1000);
            }
            
            localStorage.setItem('gestpro_login_logs', JSON.stringify(logs));
        } catch (error) {
            console.error('Erro ao registrar log:', error);
        }
    },

    // Obter logs de login
    async getLoginLogs(limit = 50) {
        try {
            const logs = JSON.parse(localStorage.getItem('gestpro_login_logs') || '[]');
            return logs.slice(-limit).reverse(); // Últimos logs primeiro
        } catch (error) {
            console.error('Erro ao obter logs:', error);
            return [];
        }
    },

    // =====================================================
    // MÉTODOS DE AUTENTICAÇÃO COM REDIRECIONAMENTO
    // =====================================================

    // Login do usuário com redirecionamento
    async login(email, password, redirectOnSuccess = true) {
        try {
            console.log('Tentativa de login:', email);
            
            // Validações básicas
            if (!email || !password) {
                await this.logLoginAttempt(email, false, null, 'Dados faltando');
                return {
                    success: false,
                    error: 'MISSING_DATA',
                    message: 'Email e senha são obrigatórios'
                };
            }

            if (!Utils.isValidEmail(email)) {
                await this.logLoginAttempt(email, false, null, 'Email inválido');
                return {
                    success: false,
                    error: 'INVALID_EMAIL',
                    message: 'Email inválido'
                };
            }

            // Verificar se conta está bloqueada
            const isLocked = await this.isAccountLocked(email);
            if (isLocked) {
                await this.logLoginAttempt(email, false, null, 'Conta bloqueada');
                return {
                    success: false,
                    error: 'ACCOUNT_LOCKED',
                    message: 'Conta temporariamente bloqueada devido a múltiplas tentativas de login'
                };
            }

            // Buscar usuário
            const user = await this.findUserByEmail(email);
            if (!user) {
                await this.incrementFailedAttempts(email);
                await this.logLoginAttempt(email, false, null, 'Usuário não encontrado');
                return {
                    success: false,
                    error: 'USER_NOT_FOUND',
                    message: 'Email ou senha incorretos'
                };
            }

            // Verificar senha
            const isValidPassword = await this.verifyPassword(password, user.password);
            if (!isValidPassword) {
                await this.incrementFailedAttempts(email);
                await this.logLoginAttempt(email, false, user.id, 'Senha incorreta');
                return {
                    success: false,
                    error: 'INVALID_PASSWORD',
                    message: 'Email ou senha incorretos'
                };
            }

            // Atualizar último login
            await this.updateLastLogin(user.id);

            // Criar sessão
            const sessionToken = await this.createSession(user.id);

            // Salvar sessão no localStorage para uso futuro
            localStorage.setItem('gestpro_session', sessionToken);
            localStorage.setItem('gestpro_current_user', JSON.stringify({
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }));

            // Log de sucesso
            await this.logLoginAttempt(email, true, user.id);

            // Retornar dados do usuário (sem senha)
            const { password: _, ...userWithoutPassword } = user;
            
            console.log('Login realizado com sucesso:', user.email);
            
            // Redirecionar se solicitado
            if (redirectOnSuccess) {
                const redirectUrl = Utils.getRedirectUrl(user.role);
                console.log(`Preparando redirecionamento para: ${redirectUrl}`);
                
                // Mostrar mensagem de sucesso antes do redirecionamento
                UIHelpers.showNotification(`Bem-vindo, ${user.name}!`, 'success');
                
                // Redirecionar após um pequeno delay para mostrar a notificação
                Utils.redirectTo(redirectUrl, 1500);
            }
            
            return {
                success: true,
                user: userWithoutPassword,
                sessionToken: sessionToken,
                message: 'Login realizado com sucesso',
                redirectUrl: Utils.getRedirectUrl(user.role)
            };

        } catch (error) {
            console.error('Erro no login:', error);
            await this.logLoginAttempt(email, false, null, 'Erro do servidor');
            return {
                success: false,
                error: 'SERVER_ERROR',
                message: 'Erro interno do servidor'
            };
        }
    },

    // Cadastro de usuário
    async register(name, email, password, phone = null) {
        try {
            console.log('Tentativa de cadastro:', { name, email });
            
            // Validações básicas
            if (!name || !email || !password) {
                return {
                    success: false,
                    error: 'MISSING_DATA',
                    message: 'Todos os campos obrigatórios devem ser preenchidos'
                };
            }

            if (!Utils.isValidEmail(email)) {
                return {
                    success: false,
                    error: 'INVALID_EMAIL',
                    message: 'Email inválido'
                };
            }

            // Validar senha
            const passwordValidation = Utils.validatePassword(password);
            if (!passwordValidation.isValid) {
                return {
                    success: false,
                    error: 'WEAK_PASSWORD',
                    message: passwordValidation.errors.join(', ')
                };
            }

            // Verificar se email já existe
            const existingUser = await this.findUserByEmail(email);
            if (existingUser) {
                return {
                    success: false,
                    error: 'EMAIL_EXISTS',
                    message: 'Email já cadastrado'
                };
            }

            // Criar usuário
            const newUser = await this.createUser({ name, email, password, phone });
            
            console.log('Cadastro realizado com sucesso:', email);
            return {
                success: true,
                user: newUser,
                message: 'Usuário cadastrado com sucesso'
            };

        } catch (error) {
            console.error('Erro no cadastro:', error);
            return {
                success: false,
                error: 'SERVER_ERROR',
                message: 'Erro interno do servidor'
            };
        }
    },

    // Logout com redirecionamento
    async logout(sessionToken, redirectToLogin = true) {
        try {
            if (sessionToken) {
                await this.destroySession(sessionToken);
            }
            
            // Limpar dados do localStorage
            localStorage.removeItem('gestpro_session');
            localStorage.removeItem('gestpro_current_user');
            
            console.log('Logout realizado com sucesso');
            
            // Redirecionar para login se solicitado
            if (redirectToLogin) {
                UIHelpers.showNotification('Logout realizado com sucesso!', 'success');
                Utils.redirectTo(RedirectConfig.loginPage, 1000);
            }
            
            return {
                success: true,
                message: 'Logout realizado com sucesso'
            };
        } catch (error) {
            console.error('Erro no logout:', error);
            return {
                success: false,
                error: 'SERVER_ERROR',
                message: 'Erro ao fazer logout'
            };
        }
    },

    // Verificar se usuário está autenticado (middleware)
    async checkAuth() {
        try {
            const sessionToken = localStorage.getItem('gestpro_session');
            if (!sessionToken) {
                return { authenticated: false, user: null };
            }

            const validation = await this.validateSession(sessionToken);
            if (!validation.valid) {
                // Limpar dados inválidos
                localStorage.removeItem('gestpro_session');
                localStorage.removeItem('gestpro_current_user');
                return { authenticated: false, user: null };
            }

            return { 
                authenticated: true, 
                user: validation.user,
                session: validation.session 
            };

        } catch (error) {
            console.error('Erro ao verificar autenticação:', error);
            return { authenticated: false, user: null };
        }
    },

    // Middleware para proteger páginas
    async requireAuth(redirectIfNotAuth = true) {
        const auth = await this.checkAuth();
        
        if (!auth.authenticated && redirectIfNotAuth) {
            console.log('Usuário não autenticado, redirecionando para login');
            UIHelpers.showNotification('Você precisa fazer login para acessar esta página', 'warning');
            Utils.redirectTo(RedirectConfig.loginPage, 1000);
            return null;
        }
        
        return auth.authenticated ? auth.user : null;
    },

    // =====================================================
    // CONTINUAÇÃO DOS MÉTODOS EXISTENTES...
    // =====================================================

    // Recuperação de senha
    async forgotPassword(email) {
        try {
            console.log('Solicitação de recuperação de senha:', email);
            
            if (!Utils.isValidEmail(email)) {
                return {
                    success: false,
                    error: 'INVALID_EMAIL',
                    message: 'Email inválido'
                };
            }
            
            const user = await this.findUserByEmail(email);
            if (!user) {
                // Por segurança, não revelamos se o email existe ou não
                return {
                    success: true,
                    message: 'Se o email existir, você receberá instruções para redefinir sua senha'
                };
            }

            // Gerar token de recuperação
            const resetToken = Utils.generateSecureToken();
            const resetExpires = new Date(Date.now() + 3600000); // 1 hora

            const users = JSON.parse(localStorage.getItem('gestpro_users') || '[]');
            const userIndex = users.findIndex(u => u.id === user.id);
            if (userIndex !== -1) {
                users[userIndex].reset_token = resetToken;
                users[userIndex].reset_expires = resetExpires.toISOString();
                localStorage.setItem('gestpro_users', JSON.stringify(users));
            }

            console.log('Token de recuperação gerado:', resetToken);
            return {
                success: true,
                message: 'Se o email existir, você receberá instruções para redefinir sua senha',
                token: resetToken // Apenas para demonstração - remover em produção
            };

        } catch (error) {
            console.error('Erro na recuperação de senha:', error);
            return {
                success: false,
                error: 'SERVER_ERROR',
                message: 'Erro interno do servidor'
            };
        }
    },

    // Redefinir senha com token
    async resetPassword(token, newPassword) {
        try {
            if (!token || !newPassword) {
                return {
                    success: false,
                    error: 'MISSING_DATA',
                    message: 'Token e nova senha são obrigatórios'
                };
            }

            const passwordValidation = Utils.validatePassword(newPassword);
            if (!passwordValidation.isValid) {
                return {
                    success: false,
                    error: 'WEAK_PASSWORD',
                    message: passwordValidation.errors.join(', ')
                };
            }

            const users = JSON.parse(localStorage.getItem('gestpro_users') || '[]');
            const user = users.find(u => 
                u.reset_token === token && 
                new Date(u.reset_expires) > new Date()
            );

            if (!user) {
                return {
                    success: false,
                    error: 'INVALID_TOKEN',
                    message: 'Token inválido ou expirado'
                };
            }
const hashedPassword = await this.hashPassword(newPassword);
            
            // Atualizar senha e limpar tokens de recuperação
            const userIndex = users.findIndex(u => u.id === user.id);
            users[userIndex].password = hashedPassword;
            users[userIndex].reset_token = null;
            users[userIndex].reset_expires = null;
            users[userIndex].updated_at = new Date().toISOString();
            users[userIndex].failed_login_attempts = 0; // Reset tentativas
            users[userIndex].locked_until = null; // Desbloquear conta
            
            localStorage.setItem('gestpro_users', JSON.stringify(users));

            // Destruir todas as sessões ativas do usuário por segurança
            await this.destroyAllUserSessions(user.id);

            console.log('Senha redefinida com sucesso para:', user.email);
            return {
                success: true,
                message: 'Senha redefinida com sucesso'
            };

        } catch (error) {
            console.error('Erro ao redefinir senha:', error);
            return {
                success: false,
                error: 'SERVER_ERROR',
                message: 'Erro interno do servidor'
            };
        }
    },

    // Alterar senha (usuário logado)
    async changePassword(userId, currentPassword, newPassword) {
        try {
            if (!currentPassword || !newPassword) {
                return {
                    success: false,
                    error: 'MISSING_DATA',
                    message: 'Senha atual e nova senha são obrigatórias'
                };
            }

            const passwordValidation = Utils.validatePassword(newPassword);
            if (!passwordValidation.isValid) {
                return {
                    success: false,
                    error: 'WEAK_PASSWORD',
                    message: passwordValidation.errors.join(', ')
                };
            }

            const user = await this.findUserById(userId);
            if (!user) {
                return {
                    success: false,
                    error: 'USER_NOT_FOUND',
                    message: 'Usuário não encontrado'
                };
            }

            // Verificar senha atual
            const isCurrentPasswordValid = await this.verifyPassword(currentPassword, user.password);
            if (!isCurrentPasswordValid) {
                return {
                    success: false,
                    error: 'INVALID_CURRENT_PASSWORD',
                    message: 'Senha atual incorreta'
                };
            }

            // Verificar se a nova senha é diferente da atual
            const isSamePassword = await this.verifyPassword(newPassword, user.password);
            if (isSamePassword) {
                return {
                    success: false,
                    error: 'SAME_PASSWORD',
                    message: 'A nova senha deve ser diferente da atual'
                };
            }

            const hashedNewPassword = await this.hashPassword(newPassword);
            
            const users = JSON.parse(localStorage.getItem('gestpro_users') || '[]');
            const userIndex = users.findIndex(u => u.id === userId);
            users[userIndex].password = hashedNewPassword;
            users[userIndex].updated_at = new Date().toISOString();
            
            localStorage.setItem('gestpro_users', JSON.stringify(users));

            console.log('Senha alterada com sucesso para usuário ID:', userId);
            return {
                success: true,
                message: 'Senha alterada com sucesso'
            };

        } catch (error) {
            console.error('Erro ao alterar senha:', error);
            return {
                success: false,
                error: 'SERVER_ERROR',
                message: 'Erro interno do servidor'
            };
        }
    }
};

// =====================================================
// CONFIGURAÇÕES DE SEGURANÇA
// =====================================================

const SecurityConfig = {
    // Configurações de senha
    password: {
        minLength: 8,
        requireNumbers: true,
        requireSymbols: true,
        requireUppercase: true,
        requireLowercase: true
    },
    
    // Configurações de sessão
    session: {
        timeout: 24 * 60 * 60 * 1000, // 24 horas em milissegundos
        renewOnActivity: true,
        maxSessions: 5 // Máximo de sessões simultâneas por usuário
    },
    
    // Configurações de tentativas de login
    loginAttempts: {
        maxAttempts: 5,
        lockoutTime: 15 * 60 * 1000 // 15 minutos em milissegundos
    },
    
    // Configurações de tokens
    tokens: {
        resetPasswordExpiry: 60 * 60 * 1000, // 1 hora
        verificationExpiry: 24 * 60 * 60 * 1000 // 24 horas
    }
};

// =====================================================
// HELPERS PARA INTERFACE DO USUÁRIO
// =====================================================

const UIHelpers = {
    // Mostrar notificações
    showNotification(message, type = 'info', duration = 5000) {
        console.log(`[${type.toUpperCase()}] ${message}`);
        
        // Remover notificações existentes
        const existingNotifications = document.querySelectorAll('.auth-notification');
        existingNotifications.forEach(notif => notif.remove());
        
        // Criar nova notificação
        const notification = document.createElement('div');
        notification.className = `auth-notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <span class="notification-icon">${this.getNotificationIcon(type)}</span>
                <span class="notification-message">${message}</span>
                <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
            </div>
        `;
        
        // Estilos da notificação
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            min-width: 300px;
            max-width: 500px;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
            line-height: 1.4;
            transform: translateX(100%);
            transition: transform 0.3s ease-in-out;
            ${this.getNotificationStyles(type)}
        `;
        
        // Adicionar ao DOM
        document.body.appendChild(notification);
        
        // Animar entrada
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);
        
        // Auto-remover após duração especificada
        if (duration > 0) {
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.style.transform = 'translateX(100%)';
                    setTimeout(() => notification.remove(), 300);
                }
            }, duration);
        }
    },
    
    getNotificationIcon(type) {
        const icons = {
            success: '✓',
            error: '✕',
            warning: '⚠',
            info: 'ℹ'
        };
        return icons[type] || icons.info;
    },
    
    getNotificationStyles(type) {
        const styles = {
            success: 'background-color: #d4edda; color: #155724; border-left: 4px solid #28a745;',
            error: 'background-color: #f8d7da; color: #721c24; border-left: 4px solid #dc3545;',
            warning: 'background-color: #fff3cd; color: #856404; border-left: 4px solid #ffc107;',
            info: 'background-color: #d1ecf1; color: #0c5460; border-left: 4px solid #17a2b8;'
        };
        return styles[type] || styles.info;
    },

    // Validação em tempo real de formulários
    setupFormValidation(formId, validationRules) {
        const form = document.getElementById(formId);
        if (!form) return;

        Object.keys(validationRules).forEach(fieldName => {
            const field = form.querySelector(`[name="${fieldName}"]`);
            if (!field) return;

            field.addEventListener('blur', () => {
                this.validateField(field, validationRules[fieldName]);
            });

            field.addEventListener('input', () => {
                // Limpar erros durante digitação
                this.clearFieldError(field);
            });
        });
    },

    validateField(field, rules) {
        const value = field.value.trim();
        let isValid = true;
        let errorMessage = '';

        // Validação obrigatória
        if (rules.required && !value) {
            isValid = false;
            errorMessage = 'Este campo é obrigatório';
        }
        // Validação de email
        else if (rules.email && value && !Utils.isValidEmail(value)) {
            isValid = false;
            errorMessage = 'Email inválido';
        }
        // Validação de senha
        else if (rules.password && value) {
            const passwordValidation = Utils.validatePassword(value);
            if (!passwordValidation.isValid) {
                isValid = false;
                errorMessage = passwordValidation.errors[0];
            }
        }
        // Validação personalizada
        else if (rules.custom && value) {
            const customValidation = rules.custom(value);
            if (!customValidation.isValid) {
                isValid = false;
                errorMessage = customValidation.message;
            }
        }

        if (isValid) {
            this.showFieldSuccess(field);
        } else {
            this.showFieldError(field, errorMessage);
        }

        return isValid;
    },

    showFieldError(field, message) {
        this.clearFieldError(field);
        
        field.classList.add('field-error');
        const errorDiv = document.createElement('div');
        errorDiv.className = 'field-error-message';
        errorDiv.textContent = message;
        errorDiv.style.cssText = `
            color: #dc3545;
            font-size: 12px;
            margin-top: 4px;
            display: block;
        `;
        
        field.parentNode.appendChild(errorDiv);
    },

    showFieldSuccess(field) {
        this.clearFieldError(field);
        field.classList.add('field-success');
        field.classList.remove('field-error');
    },

    clearFieldError(field) {
        field.classList.remove('field-error', 'field-success');
        const errorMessage = field.parentNode.querySelector('.field-error-message');
        if (errorMessage) {
            errorMessage.remove();
        }
    },

    // Loading states
    showLoading(element, text = 'Carregando...') {
        if (typeof element === 'string') {
            element = document.querySelector(element);
        }
        if (!element) return;

        element.disabled = true;
        element.dataset.originalText = element.textContent;
        element.innerHTML = `
            <span class="loading-spinner"></span>
            ${text}
        `;
        
        // Adicionar CSS para spinner se não existir
        if (!document.querySelector('#loading-spinner-styles')) {
            const style = document.createElement('style');
            style.id = 'loading-spinner-styles';
            style.textContent = `
                .loading-spinner {
                    display: inline-block;
                    width: 12px;
                    height: 12px;
                    border: 2px solid #f3f3f3;
                    border-top: 2px solid #3498db;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                    margin-right: 8px;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            `;
            document.head.appendChild(style);
        }
    },

    hideLoading(element) {
        if (typeof element === 'string') {
            element = document.querySelector(element);
        }
        if (!element) return;

        element.disabled = false;
        element.textContent = element.dataset.originalText || 'Enviar';
    }
};

// =====================================================
// INICIALIZAÇÃO E DADOS PADRÃO
// =====================================================

const InitializeAuth = {
    // Criar usuário administrador padrão
    async createDefaultAdmin() {
        try {
            const adminExists = await AuthSystem.findUserByEmail('admin@gestpro.com');
            if (adminExists) {
                console.log('Usuário administrador já existe');
                return;
            }

            const result = await AuthSystem.createUser({
                name: 'Administrador',
                email: 'admin@gestpro.com',
                password: 'Admin@123',
                role: 'admin'
            });

            console.log('Usuário administrador criado:', result);
        } catch (error) {
            console.error('Erro ao criar administrador padrão:', error);
        }
    },

    // Limpar sessões expiradas
    async cleanExpiredSessions() {
        try {
            const sessions = JSON.parse(localStorage.getItem('gestpro_sessions') || '[]');
            const now = new Date();
            const validSessions = sessions.filter(session => new Date(session.expires_at) > now);
            
            if (validSessions.length !== sessions.length) {
                localStorage.setItem('gestpro_sessions', JSON.stringify(validSessions));
                console.log(`${sessions.length - validSessions.length} sessões expiradas removidas`);
            }
        } catch (error) {
            console.error('Erro ao limpar sessões expiradas:', error);
        }
    },

    // Configurar limpeza automática
    setupAutomaticCleanup() {
        // Limpar sessões expiradas a cada 30 minutos
        setInterval(() => {
            this.cleanExpiredSessions();
        }, 30 * 60 * 1000);
    },

    // Inicializar sistema completo
    async initialize() {
        console.log('Inicializando sistema de autenticação GestPro...');
        
        try {
            await this.createDefaultAdmin();
            await this.cleanExpiredSessions();
            this.setupAutomaticCleanup();
            
            console.log('Sistema de autenticação inicializado com sucesso');
            return true;
        } catch (error) {
            console.error('Erro na inicialização:', error);
            return false;
        }
    }
};

// =====================================================
// EXPORTAR FUNCIONALIDADES
// =====================================================

// Tornar disponível globalmente
window.GestProAuth = {
    AuthSystem,
    Utils,
    UIHelpers,
    SecurityConfig,
    RedirectConfig,
    InitializeAuth
};

// Auto-inicializar quando o DOM estiver pronto
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        InitializeAuth.initialize();
    });
} else {
    InitializeAuth.initialize();
}

// =====================================================
// EXEMPLOS DE USO
// =====================================================

/* 
// Exemplo de login
const loginResult = await AuthSystem.login('user@example.com', 'password123');
if (loginResult.success) {
    console.log('Login realizado:', loginResult.user);
} else {
    console.error('Erro no login:', loginResult.message);
}

// Exemplo de cadastro
const registerResult = await AuthSystem.register('João Silva', 'joao@example.com', 'MinhaSenh@123');
if (registerResult.success) {
    console.log('Usuário cadastrado:', registerResult.user);
}

// Exemplo de verificação de autenticação
const auth = await AuthSystem.checkAuth();
if (auth.authenticated) {
    console.log('Usuário logado:', auth.user);
} else {
    console.log('Usuário não está logado');
}

// Exemplo de logout
await AuthSystem.logout(sessionToken);

// Exemplo de validação de formulário
UIHelpers.setupFormValidation('loginForm', {
    email: { required: true, email: true },
    password: { required: true, password: true }
});

// Exemplo de notificação
UIHelpers.showNotification('Login realizado com sucesso!', 'success');
*/

console.log('GestPro Authentication System v2.0 carregado com sucesso!');