
const hamburger = document.querySelector('.hamburger');
const navLinks = document.querySelector('.nav_links');

function toggleMobileNav() {
    hamburger.classList.toggle('active');
    navLinks.classList.toggle('active');
}

function closeNavMobile() {
    hamburger.classList.remove('active');
    navLinks.classList.remove('active');
}

function toggleNotifications() {
    const dropdown = document.getElementById('notificationDropdown');
    dropdown.classList.toggle('show');
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

// Add click event to hamburger menu
hamburger.addEventListener('click', toggleMobileNav);
