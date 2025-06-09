// auth-client.js - Sistema de Autenticação Frontend
// Gerencia login, logout e redirecionamento automático
class AuthSystem {
    constructor() {
        this.baseURL = window.location.origin;
        this.token = localStorage.getItem('gestpro_token');
        this.user = JSON.parse(localStorage.getItem('gestpro_user') || 'null');
        
        // Configurações
        this.config = {
            tokenKey: 'gestpro_token',
            userKey: 'gestpro_user',
            loginEndpoint: '/api/auth/login',
            verifyEndpoint: '/api/auth/verify',
            logoutEndpoint: '/api/auth/logout',
            registerEndpoint: '/api/auth/register'
        };
        
        // Estado do sistema
        this.isLoading = false;
        this.loginAttempts = 0;
        this.maxLoginAttempts = 5;
        
        // Inicializar sistema
        this.init();
    }

    init() {
        // Verificar se está em uma página protegida
        const protectedPages = ['/dashboard', '/admin', '/manager'];
        const currentPath = window.location.pathname;
        
        if (protectedPages.some(page => currentPath.startsWith(page))) {
            this.verifyToken();
        }
        
        // Auto-verificar token se existir
        if (this.token && currentPath === '/') {
            this.verifyTokenAndRedirect();
        }

        // Configurar interceptadores de requisição
        this.setupRequestInterceptors();
        
        // Verificar parâmetros de erro na URL
        this.checkUrlErrors();
    }

    // ==========================================
    // MÉTODOS DE AUTENTICAÇÃO
    // ==========================================
    
    async login(email, password) {
        try {
            this.showLoading(true);
            this.clearErrors();
            
            // Validações básicas
            if (!this.validateEmail(email)) {
                throw new Error('Email inválido');
            }
            
            if (!password || password.length < 3) {
                throw new Error('Senha deve ter pelo menos 3 caracteres');
            }

            const response = await this.makeRequest(this.config.loginEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (!response.ok) {
                this.loginAttempts++;
                throw new Error(data.message || 'Erro no login');
            }

            // Salvar dados do usuário
            this.saveUserData(data.token, data.user);
            
            // Mostrar sucesso
            this.showSuccess('Login realizado com sucesso!');
            
            // Redirecionar após pequeno delay
            setTimeout(() => {
                window.location.href = data.redirectUrl || '/dashboard';
            }, 1000);

            return data;

        } catch (error) {
            console.error('Erro no login:', error);
            this.showError(error.message);
            
            // Bloquear temporariamente após muitas tentativas
            if (this.loginAttempts >= this.maxLoginAttempts) {
                this.showError('Muitas tentativas falhadas. Tente novamente em alguns minutos.');
                this.blockLogin();
            }
            
            throw error;
        } finally {
            this.showLoading(false);
        }
    }

    async register(userData) {
        try {
            this.showLoading(true);
            this.clearErrors();

            // Validações
            if (!userData.name || userData.name.trim().length < 2) {
                throw new Error('Nome deve ter pelo menos 2 caracteres');
            }

            if (!this.validateEmail(userData.email)) {
                throw new Error('Email inválido');
            }

            if (!this.validatePassword(userData.password)) {
                throw new Error('Senha deve ter pelo menos 8 caracteres, incluir maiúsculas e números');
            }

            if (userData.password !== userData.confirmPassword) {
                throw new Error('Senhas não coincidem');
            }

            const response = await this.makeRequest(this.config.registerEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: userData.name.trim(),
                    email: userData.email.toLowerCase(),
                    password: userData.password,
                    phone: userData.phone || null
                })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'Erro no cadastro');
            }

            this.showSuccess('Cadastro realizado com sucesso! Faça login para continuar.');
            
            // Redirecionar para login após delay
            setTimeout(() => {
                window.location.href = '/';
            }, 2000);

            return data;

        } catch (error) {
            console.error('Erro no cadastro:', error);
            this.showError(error.message);
            throw error;
        } finally {
            this.showLoading(false);
        }
    }

    async logout() {
        try {
            // Tentar fazer logout no servidor
            if (this.token) {
                await this.makeRequest(this.config.logoutEndpoint, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.token}`,
                        'Content-Type': 'application/json'
                    }
                });
            }
        } catch (error) {
            console.warn('Erro ao fazer logout no servidor:', error);
        } finally {
            // Limpar dados locais independentemente do resultado
            this.clearUserData();
            window.location.href = '/';
        }
    }

    async verifyToken() {
        if (!this.token) {
            this.redirectToLogin();
            return false;
        }

        try {
            const response = await this.makeRequest(this.config.verifyEndpoint, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) {
                throw new Error('Token inválido');
            }

            const data = await response.json();
            
            // Atualizar dados do usuário
            this.user = data.user;
            localStorage.setItem(this.config.userKey, JSON.stringify(this.user));
            
            return true;

        } catch (error) {
            console.warn('Token inválido:', error);
            this.clearUserData();
            this.redirectToLogin();
            return false;
        }
    }

    async verifyTokenAndRedirect() {
        const isValid = await this.verifyToken();
        
        if (isValid && this.user) {
            // Redirecionar baseado no role do usuário
            let redirectUrl = '/dashboard';
            
            if (this.user.role === 'admin') {
                redirectUrl = '/admin';
            } else if (this.user.role === 'manager') {
                redirectUrl = '/manager';
            }
            
            window.location.href = redirectUrl;
        }
    }

    // ==========================================
    // MÉTODOS DE GERENCIAMENTO DE DADOS
    // ==========================================
    
    saveUserData(token, user) {
        this.token = token;
        this.user = user;
        
        localStorage.setItem(this.config.tokenKey, token);
        localStorage.setItem(this.config.userKey, JSON.stringify(user));
    }

    clearUserData() {
        this.token = null;
        this.user = null;
        
        localStorage.removeItem(this.config.tokenKey);
        localStorage.removeItem(this.config.userKey);
    }

    getCurrentUser() {
        return this.user;
    }

    isAuthenticated() {
        return !!(this.token && this.user);
    }

    hasRole(role) {
        return this.user && this.user.role === role;
    }

    hasAnyRole(roles) {
        return this.user && roles.includes(this.user.role);
    }

    // ==========================================
    // MÉTODOS DE VALIDAÇÃO
    // ==========================================
    
    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    validatePassword(password) {
        if (!password || password.length < 8) return false;
        
        const hasUpperCase = /[A-Z]/.test(password);
        const hasNumbers = /\d/.test(password);
        
        return hasUpperCase && hasNumbers;
    }

    // ==========================================
    // MÉTODOS DE REQUISIÇÃO HTTP
    // ==========================================
    
    async makeRequest(url, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json'
            }
        };

        // Adicionar token se disponível
        if (this.token && !options.headers?.Authorization) {
            defaultOptions.headers.Authorization = `Bearer ${this.token}`;
        }

        const finalOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };

        const response = await fetch(`${this.baseURL}${url}`, finalOptions);
        
        // Verificar se token expirou
        if (response.status === 401 || response.status === 403) {
            this.clearUserData();
            
            // Só redirecionar se não for uma tentativa de login
            if (!url.includes('/login')) {
                this.redirectToLogin();
            }
        }

        return response;
    }

    setupRequestInterceptors() {
        // Interceptar fetch global para adicionar token automaticamente
        const originalFetch = window.fetch;
        
        window.fetch = async (url, options = {}) => {
            // Se for uma requisição para API e tiver token
            if (typeof url === 'string' && url.startsWith('/api') && this.token) {
                options.headers = {
                    ...options.headers,
                    'Authorization': `Bearer ${this.token}`
                };
            }
            
            return originalFetch(url, options);
        };
    }

    // ==========================================
    // MÉTODOS DE UI E FEEDBACK
    // ==========================================
    
    showLoading(show) {
        this.isLoading = show;
        
        // Procurar por elementos de loading
        const loadingElements = document.querySelectorAll('.loading, .spinner, [data-loading]');
        const submitButtons = document.querySelectorAll('button[type="submit"], .btn-submit');
        
        loadingElements.forEach(el => {
            el.style.display = show ? 'block' : 'none';
        });
        
        submitButtons.forEach(btn => {
            btn.disabled = show;
            if (show) {
                btn.classList.add('loading');
                btn.textContent = 'Aguarde...';
            } else {
                btn.classList.remove('loading');
                // Restaurar texto original (se houver data-original-text)
                if (btn.dataset.originalText) {
                    btn.textContent = btn.dataset.originalText;
                }
            }
        });
    }

    showError(message) {
        console.error('Auth Error:', message);
        
        // Procurar por container de erro
        const errorContainer = document.querySelector('.error-message, .alert-error, [data-error]');
        
        if (errorContainer) {
            errorContainer.textContent = message;
            errorContainer.style.display = 'block';
            errorContainer.classList.add('show');
        } else {
            // Fallback: usar alert se não houver container
            alert('Erro: ' + message);
        }

        // Auto-esconder após 5 segundos
        setTimeout(() => this.clearErrors(), 5000);
    }

    showSuccess(message) {
        console.log('Auth Success:', message);
        
        const successContainer = document.querySelector('.success-message, .alert-success, [data-success]');
        
        if (successContainer) {
            successContainer.textContent = message;
            successContainer.style.display = 'block';
            successContainer.classList.add('show');
        } else {
            // Criar notificação temporária
            this.createToast(message, 'success');
        }

        // Auto-esconder após 3 segundos
        setTimeout(() => this.clearSuccess(), 3000);
    }

    clearErrors() {
        const errorElements = document.querySelectorAll('.error-message, .alert-error, [data-error]');
        errorElements.forEach(el => {
            el.style.display = 'none';
            el.classList.remove('show');
        });
    }

    clearSuccess() {
        const successElements = document.querySelectorAll('.success-message, .alert-success, [data-success]');
        successElements.forEach(el => {
            el.style.display = 'none';
            el.classList.remove('show');
        });
    }

    createToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${type === 'success' ? '#4CAF50' : type === 'error' ? '#f44336' : '#2196F3'};
            color: white;
            padding: 12px 20px;
            border-radius: 4px;
            z-index: 10000;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            animation: slideIn 0.3s ease;
        `;
        toast.textContent = message;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    // ==========================================
    // MÉTODOS DE REDIRECIONAMENTO
    // ==========================================
    
    redirectToLogin() {
        const currentPath = window.location.pathname;
        if (currentPath !== '/') {
            window.location.href = '/?redirect=' + encodeURIComponent(currentPath);
        }
    }

    checkUrlErrors() {
        const urlParams = new URLSearchParams(window.location.search);
        const error = urlParams.get('error');
        
        if (error) {
            const errorMessages = {
                'login_required': 'É necessário fazer login para acessar esta página',
                'invalid_session': 'Sessão inválida. Faça login novamente',
                'invalid_token': 'Token de acesso inválido',
                'insufficient_permissions': 'Você não tem permissão para acessar esta página'
            };
            
            this.showError(errorMessages[error] || 'Erro de autenticação');
            
            // Limpar parâmetro da URL
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }

    blockLogin() {
        const blockUntil = Date.now() + (5 * 60 * 1000); // 5 minutos
        localStorage.setItem('login_blocked_until', blockUntil.toString());
        
        setTimeout(() => {
            this.loginAttempts = 0;
            localStorage.removeItem('login_blocked_until');
        }, 5 * 60 * 1000);
    }

    isLoginBlocked() {
        const blockUntil = localStorage.getItem('login_blocked_until');
        if (!blockUntil) return false;
        
        return Date.now() < parseInt(blockUntil);
    }

    // ==========================================
    // MÉTODOS DE UTILIDADE
    // ==========================================
    
    formatUserName(user = this.user) {
        if (!user) return 'Usuário';
        return user.name || user.email || 'Usuário';
    }

    getRoleDisplayName(role = this.user?.role) {
        const roles = {
            'admin': 'Administrador',
            'manager': 'Gerente',
            'user': 'Usuário'
        };
        return roles[role] || 'Usuário';
    }

    // ==========================================
    // MÉTODOS PARA INTEGRAÇÃO COM UI
    // ==========================================
    
    setupLoginForm(formSelector = '#loginForm') {
        const form = document.querySelector(formSelector);
        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (this.isLoginBlocked()) {
                this.showError('Login temporariamente bloqueado. Tente novamente em alguns minutos.');
                return;
            }
            
            const formData = new FormData(form);
            const email = formData.get('email');
            const password = formData.get('password');
            
            try {
                await this.login(email, password);
            } catch (error) {
                // Erro já tratado no método login
            }
        });
    }

    setupRegisterForm(formSelector = '#registerForm') {
        const form = document.querySelector(formSelector);
        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(form);
            const userData = {
                name: formData.get('name'),
                email: formData.get('email'),
                password: formData.get('password'),
                confirmPassword: formData.get('confirmPassword'),
                phone: formData.get('phone')
            };
            
            try {
                await this.register(userData);
            } catch (error) {
                // Erro já tratado no método register
            }
        });
    }

    setupLogoutButtons(selector = '[data-logout], .logout-btn') {
        const buttons = document.querySelectorAll(selector);
        buttons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                
                if (confirm('Deseja realmente sair do sistema?')) {
                    this.logout();
                }
            });
        });
    }

    // Atualizar informações do usuário na interface
    updateUserInterface() {
        if (!this.user) return;

        // Atualizar nome do usuário
        const userNameElements = document.querySelectorAll('[data-user-name]');
        userNameElements.forEach(el => {
            el.textContent = this.formatUserName();
        });

        // Atualizar email do usuário
        const userEmailElements = document.querySelectorAll('[data-user-email]');
        userEmailElements.forEach(el => {
            el.textContent = this.user.email;
        });

        // Atualizar role do usuário
        const userRoleElements = document.querySelectorAll('[data-user-role]');
        userRoleElements.forEach(el => {
            el.textContent = this.getRoleDisplayName();
        });

        // Mostrar/esconder elementos baseados no role
        const adminElements = document.querySelectorAll('[data-admin-only]');
        adminElements.forEach(el => {
            el.style.display = this.hasRole('admin') ? 'block' : 'none';
        });

        const managerElements = document.querySelectorAll('[data-manager-only]');
        managerElements.forEach(el => {
            el.style.display = this.hasAnyRole(['admin', 'manager']) ? 'block' : 'none';
        });
    }
}

// ==========================================
// INICIALIZAÇÃO AUTOMÁTICA
// ==========================================

// Criar instância global
const Auth = new AuthSystem();

// Configurar formulários automaticamente quando DOM carregar
document.addEventListener('DOMContentLoaded', () => {
    Auth.setupLoginForm();
    Auth.setupRegisterForm();
    Auth.setupLogoutButtons();
    Auth.updateUserInterface();
});

// Exportar para uso em módulos
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthSystem;
}

// Adicionar CSS para animações dos toasts
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    
    .loading {
        pointer-events: none;
        opacity: 0.7;
    }
`;
document.head.appendChild(style);