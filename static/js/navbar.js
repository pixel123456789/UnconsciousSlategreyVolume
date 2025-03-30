
document.addEventListener('DOMContentLoaded', function() {
    const hamburger = document.querySelector('.hamburger');
    const navLinks = document.querySelector('.nav_links');
    const nav = document.getElementById('nav');

    window.closeNavMobile = function() {
        if (hamburger && navLinks) {
            hamburger.classList.remove('active');
            navLinks.classList.remove('active');
        }
    }

    document.addEventListener('click', function(event) {
        if (navLinks.classList.contains('active') && !nav.contains(event.target)) {
            closeNavMobile();
        }
    });

    window.toggleNotifications = function() {
        const dropdown = document.getElementById('notificationDropdown');
        if (dropdown) {
            dropdown.classList.toggle('show');
        }
    }

    if (hamburger && navLinks) {
        hamburger.addEventListener('click', function() {
            hamburger.classList.toggle('active');
            navLinks.classList.toggle('active');
        });
    }

    // Close notifications dropdown when clicking outside
    window.onclick = function(event) {
        if (!event.target.matches('.notification-icon')) {
            const dropdowns = document.getElementsByClassName('notification-dropdown');
            for (let dropdown of dropdowns) {
                if (dropdown.classList.contains('show')) {
                    dropdown.classList.remove('show');
                }
            }
        }
    }
});
