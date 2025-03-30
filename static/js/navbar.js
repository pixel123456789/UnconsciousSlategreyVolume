
document.addEventListener('DOMContentLoaded', function() {
    const hamburger = document.querySelector('.hamburger');
    const navLinks = document.querySelector('.nav_links');
    const navButtons = document.querySelectorAll('.nav_btn');

    // Close nav when clicking outside
    document.addEventListener('click', function(e) {
        if (!navLinks.contains(e.target) && !hamburger.contains(e.target) && navLinks.classList.contains('active')) {
            closeNavMobile();
        }
    });

    // Close nav when pressing escape
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && navLinks.classList.contains('active')) {
            closeNavMobile();
        }
    });

    window.closeNavMobile = function() {
        if (hamburger && navLinks) {
            hamburger.classList.remove('active');
            navLinks.classList.remove('active');
            document.body.style.overflow = '';
        }
    }

    // Prevent scroll when nav is open
    if (hamburger && navLinks) {
        hamburger.addEventListener('click', function(e) {
            e.stopPropagation();
            hamburger.classList.toggle('active');
            navLinks.classList.toggle('active');
            document.body.style.overflow = navLinks.classList.contains('active') ? 'hidden' : '';
        });
    }

    // Close nav when clicking a nav button
    navButtons.forEach(button => {
        button.addEventListener('click', closeNavMobile);
    });

    // Handle notifications
    window.toggleNotifications = function() {
        const dropdown = document.getElementById('notificationDropdown');
        if (dropdown) {
            dropdown.classList.toggle('show');
        }
    }

    // Add touch event handlers for mobile
    if ('ontouchstart' in window) {
        document.querySelectorAll('.card, .action-button').forEach(element => {
            element.addEventListener('touchstart', function() {
                this.classList.add('touch-active');
            });
            element.addEventListener('touchend', function() {
                this.classList.remove('touch-active');
            });
        });
    }
});
