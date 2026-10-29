const container = document.querySelector('.container');
const loginLink = document.querySelector('.SignInLink');
const registerLink = document.querySelector('.SignUpLink');

// Toggle to Register mode
registerLink.addEventListener('click', (e) => {
    e.preventDefault();
    container.classList.add('active');
});

// Toggle back to Login mode
loginLink.addEventListener('click', (e) => {
    e.preventDefault();
    container.classList.remove('active');
});

