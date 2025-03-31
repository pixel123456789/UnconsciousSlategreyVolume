
// File management
function deleteFile(fileId) {
    if (confirm('Are you sure you want to delete this file?')) {
        fetch(`/delete_file/${fileId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Error deleting file: ' + data.error);
            }
        });
    }
}

function uploadFile(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const projectId = window.location.pathname.split('/').pop();
    
    fetch(`/upload_file/${projectId}`, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            location.reload();
        } else {
            alert('Error uploading file');
        }
    });
}
