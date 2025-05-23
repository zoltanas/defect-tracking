function showPopup() {
    const popup = document.getElementById('invitePopup');
    if (popup) {
        popup.style.display = 'flex';
    }
}

function closePopup() {
    const popup = document.getElementById('invitePopup');
    if (popup) {
        popup.style.display = 'none';
        // Redirect to project detail page after closing
        const projectId = new URLSearchParams(window.location.search).get('project_id') || 
                         document.querySelector('select[name="project_id"]').value;
        window.location.href = `/project/${projectId}`;
    }
}

function copyInviteLink() {
    const linkInput = document.getElementById('inviteLink');
    linkInput.select();
    try {
        document.execCommand('copy');
        alert('Link copied to clipboard!');
    } catch (err) {
        console.error('Failed to copy link:', err);
        alert('Failed to copy link. Please copy it manually.');
    }
}