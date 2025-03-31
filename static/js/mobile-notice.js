
function dismissMobileNotice() {
    const notice = document.getElementById('mobileNotice');
    if (notice) {
        notice.style.display = 'none';
        localStorage.setItem('mobileNoticeHidden', 'true');
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const notice = document.getElementById('mobileNotice');
    if (notice && localStorage.getItem('mobileNoticeHidden')) {
        notice.style.display = 'none';
    }
});
