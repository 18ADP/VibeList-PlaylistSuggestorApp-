document.addEventListener('DOMContentLoaded', () => {
    const API_BASE_URL = 'https://vibelist-playlistsuggester.onrender.com';
    const registerForm = document.getElementById('register-form');
    const loginForm = document.getElementById('login-form');

    if (registerForm) {
        registerForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value.trim();
            if (!email || !password) {
                alert('Please fill in all fields.');
                return;
            }
            try {
                const response = await fetch(`${API_BASE_URL}/register`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password }),
                });
                if (response.ok) {
                    alert('Registration successful! Please login.');
                    window.location.href = 'login.html';
                } else {
                    const errorData = await response.json();
                    alert(`Registration failed: ${errorData.detail || 'Unknown error'}`);
                }
            } catch (error) {
                console.error('Error during registration:', error);
                alert('An error occurred. Please try again later.');
            }
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value.trim();
            if (!email || !password) {
                alert('Please enter both email and password.');
                return;
            }
            const formData = new URLSearchParams();
            formData.append('username', email);
            formData.append('password', password);
            try {
                const response = await fetch(`${API_BASE_URL}/token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: formData,
                });
                if (response.ok) {
                    const data = await response.json();
                    localStorage.setItem('vibelist_token', data.access_token);
                    alert('Login successful!');
                    window.location.href = 'index.html'; 
                } else {
                    alert('Login failed: Invalid email or password.');
                }
            } catch (error) {
                console.error('Error during login:', error);
                alert('An error occurred. Please check your connection and try again.');
            }
        });
    }

});

