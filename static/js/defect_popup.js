function showDefectPopup(defectData) {
    console.log("showDefectPopup called with:", defectData);

    document.getElementById('defect-popup-description').textContent = defectData.description || 'N/A';
    document.getElementById('defect-popup-status').textContent = defectData.status || 'N/A';
    document.getElementById('defect-popup-creator').textContent = defectData.creator ? defectData.creator.username : (defectData.creator_username || 'N/A');
    
    let creationDate = 'N/A';
    if (defectData.creation_date) {
        creationDate = new Date(defectData.creation_date).toLocaleString();
    }
    document.getElementById('defect-popup-creation-date').textContent = creationDate;

    const imagesContainer = document.getElementById('defect-popup-images');
    imagesContainer.innerHTML = ''; // Clear previous images

    if (defectData.attachments && defectData.attachments.length > 0) {
        defectData.attachments.forEach(attachment => {
            if (attachment.file_path) { // Assuming file_path points to an image
                const img = document.createElement('img');
                // Ensure the path is correct, prepending /static/ if it's a relative path from the static folder
                img.src = `/static/${attachment.file_path}`; 
                img.alt = defectData.description || 'Defect image';
                img.className = 'w-24 h-24 object-cover rounded border'; // Basic styling
                imagesContainer.appendChild(img);
            }
        });
    } else {
        imagesContainer.textContent = 'No attachments.';
    }

    document.getElementById('defectSummaryPopup').classList.remove('hidden');
    document.getElementById('defectSummaryPopup').classList.add('flex');
}

function hideDefectPopup() {
    console.log("hideDefectPopup called");
    document.getElementById('defectSummaryPopup').classList.add('hidden');
    document.getElementById('defectSummaryPopup').classList.remove('flex');
    // Optional: Clear content when hiding
    document.getElementById('defect-popup-description').textContent = '';
    document.getElementById('defect-popup-status').textContent = '';
    document.getElementById('defect-popup-creator').textContent = '';
    document.getElementById('defect-popup-creation-date').textContent = '';
    document.getElementById('defect-popup-images').innerHTML = '';
}

document.addEventListener('DOMContentLoaded', () => {
    const closeButton = document.getElementById('defect-popup-close');
    if (closeButton) {
        closeButton.addEventListener('click', hideDefectPopup);
    }

    // Hide popup if clicked outside the content area (optional)
    const popup = document.getElementById('defectSummaryPopup');
    if (popup) {
        popup.addEventListener('click', function(event) {
            if (event.target === popup) { // Check if the click is on the backdrop
                hideDefectPopup();
            }
        });
    }
});
