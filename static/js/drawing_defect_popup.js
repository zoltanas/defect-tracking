// static/js/drawing_defect_popup.js
function openDefectInfoPopup(defect) {
    // defect object should contain: description, creator_name, creation_date_formatted, defect_id
    const popup = document.getElementById('defectInfoPopup');
    if (!popup) {
        console.error('Defect info popup element not found.');
        return;
    }

    document.getElementById('popupDefectDescription').textContent = defect.description;
    document.getElementById('popupDefectDescription').dataset.defectId = defect.defect_id; // Store defect_id for redirection
    document.getElementById('popupDefectAuthor').textContent = defect.creator_name;
    document.getElementById('popupDefectDate').textContent = defect.creation_date_formatted;

    const popupImage = document.getElementById('popupDefectImage');
    const popupNoImage = document.getElementById('popupDefectNoImage');

    if (defect.attachment_thumbnail_url) {
        popupImage.src = defect.attachment_thumbnail_url;
        popupImage.classList.remove('hidden');
        // Ensure no image message is hidden
        if (!popupNoImage.classList.contains('hidden')) {
            popupNoImage.classList.add('hidden');
        }
    } else {
        popupImage.src = '#'; // Clear src
        if (!popupImage.classList.contains('hidden')) {
            popupImage.classList.add('hidden');
        }
        popupNoImage.classList.remove('hidden');
    }

    // Make the description clickable to redirect to defect detail page
    const descriptionElement = document.getElementById('popupDefectDescription');
    descriptionElement.style.cursor = 'pointer';
    descriptionElement.style.textDecoration = 'underline';
    descriptionElement.onclick = function() {
        window.location.href = `/defect/${this.dataset.defectId}`;
    };

    popup.classList.remove('hidden');
}

function closeDefectInfoPopup() {
    const popup = document.getElementById('defectInfoPopup');
    if (popup) {
        popup.classList.add('hidden');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const closeButton = document.getElementById('closeDefectPopup');
    if (closeButton) {
        closeButton.addEventListener('click', closeDefectInfoPopup);
    }

    const popup = document.getElementById('defectInfoPopup');
    if (popup) {
        // Close popup if background is clicked
        popup.addEventListener('click', (event) => {
            if (event.target === popup) {
                closeDefectInfoPopup();
            }
        });
    }
});
