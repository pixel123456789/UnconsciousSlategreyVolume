
const hamburger = document.querySelector('.hamburger');
const navLinks = document.querySelector('.nav_links');

function closeNav() {
  hamburger?.classList.remove('active');
  navLinks?.classList.remove('active');
  navLinks.style.transform = 'translateX(100%)';
}

function toggleNotifications() {
  const dropdown = document.getElementById('notificationDropdown');
  dropdown?.classList.toggle('show');
}

hamburger?.addEventListener('click', (e) => {
  e.stopPropagation();
  hamburger.classList.toggle('active');
  navLinks.classList.toggle('active');
  navLinks.style.transform = navLinks.classList.contains('active') ? 'translateX(0)' : 'translateX(100%)';
});

document.addEventListener('click', (e) => {
  if (!hamburger?.contains(e.target) && !navLinks?.contains(e.target)) {
    closeNav();
  }
  
  const dropdown = document.getElementById('notificationDropdown');
  const notificationIcon = document.querySelector('.notification-icon');
  if (!notificationIcon?.contains(e.target) && !dropdown?.contains(e.target)) {
    dropdown?.classList.remove('show');
  }
});

document.querySelectorAll('.nav_btn').forEach(link => {
  link.addEventListener('click', closeNav);
});
