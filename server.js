const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const db = require('./assets/js/db'); // Certifique-se de que o caminho está certo e db.js está correto

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname)); // Serve arquivos da raiz

// Página inicial
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Rota para o dashboard
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Dashboard.html'));
});

// ===== ROTAS DA API =====

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email e senha são obrigatórios' });
        }

        const query = 'SELECT * FROM users WHERE email = ?';
        const [users] = await db.execute(query, [email]);

        if (users.length === 0) {
            return res.status(404).json({ message: 'Usuário não encontrado', redirect: 'register' });
        }

        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Senha incorreta' });
        }

        console.log(`✅ Login bem-sucedido para: ${user.email}`);
        res.json({
            message: 'Login realizado com sucesso',
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            },
            redirect: '/dashboard'  // adiciona a URL para redirecionamento no frontend
        });

    } catch (error) {
        console.error('❌ Erro no login:', error);
        res.status(500).json({ message: 'Erro interno do servidor' });
    }
});

// Cadastro
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ message: 'Todos os campos são obrigatórios' });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: 'A senha deve ter pelo menos 6 caracteres' });
        }

        const checkQuery = 'SELECT * FROM users WHERE email = ?';
        const [existingUsers] = await db.execute(checkQuery, [email]);

        if (existingUsers.length > 0) {
            return res.status(409).json({ message: 'Este email já está cadastrado' });
        }

        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const insertQuery = `
            INSERT INTO users (name, email, password, created_at, updated_at) 
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        `;
        const [result] = await db.execute(insertQuery, [name, email, hashedPassword]);

        console.log(`✅ Novo usuário cadastrado: ${email}`);
        res.status(201).json({
            message: 'Usuário cadastrado com sucesso',
            userId: result.insertId
        });

    } catch (error) {
        console.error('❌ Erro no cadastro:', error);
        res.status(500).json({ message: 'Erro interno do servidor' });
    }
});

// Recuperação de senha
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Email é obrigatório' });
        }

        const query = 'SELECT * FROM users WHERE email = ?';
        const [users] = await db.execute(query, [email]);

        if (users.length === 0) {
            return res.status(404).json({ message: 'Email não encontrado.' });
        }

        // Simulação de email
        const resetToken = Math.random().toString(36).substring(2, 15);
        const updateQuery = 'UPDATE users SET reset_token = ?, reset_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE email = ?';
        await db.execute(updateQuery, [resetToken, email]);

        console.log(`📧 SIMULAÇÃO DE EMAIL PARA: ${email}`);
        console.log(`http://localhost:${PORT}/reset-password?token=${resetToken}`);

        res.json({ message: 'Instruções de recuperação enviadas para seu email' });

    } catch (error) {
        console.error('❌ Erro na recuperação de senha:', error);
        res.status(500).json({ message: 'Erro interno do servidor' });
    }
});

// Status da API
app.get('/api/status', (req, res) => {
    res.json({ status: 'Servidor GestPro funcionando!', timestamp: new Date() });
});

// Middleware para 404
app.use((req, res) => {
    res.status(404).json({ message: 'Rota não encontrada' });
});

// Middleware para erros genéricos
app.use((error, req, res, next) => {
    console.error('❌ Erro não tratado:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
});

// Inicializar servidor
app.listen(PORT, () => {
    console.log(`🚀 Servidor GestPro rodando na porta ${PORT}`);
    console.log(`📱 Acesse: http://localhost:${PORT}`);
    console.log(`🔒 Sistema de login ativo`);
});

module.exports = app;
