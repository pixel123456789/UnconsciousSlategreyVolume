
document.addEventListener('DOMContentLoaded', () => {
    const hamburger = document.querySelector('.hamburger');
    const closeNav = document.querySelector('.close-nav');
    const navLinks = document.querySelector('.nav_links');
    
    hamburger?.addEventListener('click', (e) => {
        e.stopPropagation();
        hamburger.classList.toggle('active');
        navLinks.classList.toggle('active');
        closeNav.classList.toggle('active');
    });

    // Close menu when clicking outside
    closeNav?.addEventListener('click', () => {
        hamburger?.classList.remove('active');
        navLinks?.classList.remove('active');
    });

    document.addEventListener('click', (e) => {
        if (!hamburger?.contains(e.target) && !navLinks?.contains(e.target) && !closeNav?.contains(e.target)) {
            hamburger?.classList.remove('active');
            navLinks?.classList.remove('active');
        }
    });

    // Close menu when clicking a link
    document.querySelectorAll('.nav_btn').forEach(link => {
        link.addEventListener('click', () => {
            hamburger?.classList.remove('active');
            navLinks?.classList.remove('active');
        });
    });
});
