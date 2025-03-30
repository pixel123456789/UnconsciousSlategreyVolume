
// Wait for DOM to be loaded
document.addEventListener('DOMContentLoaded', function() {
  const hamburger = document.querySelector('.hamburger');
  const navLinks = document.querySelector('.nav_links');

  window.toggleMobileNav = function() {
    hamburger.classList.toggle('active');
    navLinks.classList.toggle('active');
  }

  window.closeNavMobile = function() {
    hamburger.classList.remove('active');
    navLinks.classList.remove('active');
  }

  window.toggleNotifications = function() {
    const dropdown = document.getElementById('notificationDropdown');
    if (dropdown) {
      dropdown.classList.toggle('show');
    }
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
  if (hamburger) {
    hamburger.addEventListener('click', toggleMobileNav);
  }
});
