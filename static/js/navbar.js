
const hamburger = document.querySelector('.hamburger');
const navLinks = document.querySelector('.nav_links');

function closeNavMobile() {
  hamburger?.classList.remove('active');
  navLinks?.classList.remove('active');
}

function toggleNotifications() {
  const dropdown = document.getElementById('notificationDropdown');
  dropdown?.classList.toggle('show');
}

// Toggle mobile menu
hamburger?.addEventListener('click', () => {
  hamburger.classList.toggle('active');
  navLinks?.classList.toggle('active');
});

// Close menu when clicking outside
document.addEventListener('click', (e) => {
  if (!hamburger?.contains(e.target) && !navLinks?.contains(e.target)) {
    closeNavMobile();
  }
});

// Close notifications when clicking outside
document.addEventListener('click', (e) => {
  const dropdown = document.getElementById('notificationDropdown');
  const notificationIcon = document.querySelector('.notification-icon');
  if (!notificationIcon?.contains(e.target) && !dropdown?.contains(e.target)) {
    dropdown?.classList.remove('show');
  }
});
