
document.addEventListener('DOMContentLoaded', () => {
    const hamburger = document.querySelector('.hamburger');
    const navLinks = document.querySelector('.nav_links');
    
    hamburger?.addEventListener('click', (e) => {
        e.stopPropagation();
        hamburger.classList.toggle('active');
        navLinks.classList.toggle('active');
        navLinks.style.transform = navLinks.classList.contains('active') ? 'translateX(0)' : 'translateX(100%)';
    });

    window.closeNavMobile = () => {
        hamburger?.classList.remove('active');
        navLinks?.classList.remove('active');
    };

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
        if (!hamburger?.contains(e.target) && !navLinks?.contains(e.target)) {
            closeNavMobile();
        }
    });

    document.addEventListener('click', (e) => {
        if (!hamburger?.contains(e.target) && !navLinks?.contains(e.target)) {
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
