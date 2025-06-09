async function login() {
  const email = document.getElementById('loginEmail').value.trim();
  const password = document.getElementById('loginPassword').value;

  if (!email || !password) {
    alert('Por favor, preencha e-mail e senha');
    return;
  }

  const response = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  const result = await response.json();

  if (result.success) {
    window.location.href = '/Dashboard.html';
  } else {
    // Se usuário não encontrado, perguntar se quer cadastrar
    if (result.message === 'Usuário não encontrado') {
      const wantRegister = confirm('Usuário não encontrado. Deseja criar uma conta?');
      if (wantRegister) {
        // Mostrar formulário de cadastro e colocar email preenchido
        document.getElementById('registerSection').style.display = 'block';
        document.getElementById('email').value = email;
      }
    } else {
      alert(result.message);
    }
  }
}

async function register() {
  const name = document.getElementById('name').value.trim();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirmPassword').value;

  if (!name || !email || !password || !confirmPassword) {
    alert('Preencha todos os campos');
    return;
  }

  if (password !== confirmPassword) {
    alert('As senhas não coincidem');
    return;
  }

  const response = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
  });

  const result = await response.json();

  if (result.success) {
    alert('Usuário cadastrado com sucesso! Faça login.');
    // Esconder formulário de cadastro e limpar campos
    document.getElementById('registerSection').style.display = 'none';
    document.getElementById('name').value = '';
    document.getElementById('email').value = '';
    document.getElementById('password').value = '';
    document.getElementById('confirmPassword').value = '';
  } else {
    alert(result.message); // "Usuário já existe"
  }
}
