// static/js/drawing_defect_popup.js
function openDefectInfoPopup(defect) {
    console.log("DEBUG_POPUP_JS: openDefectInfoPopup called with defect object:", JSON.parse(JSON.stringify(defect)));
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

    console.log("DEBUG_POPUP_JS: Defect ID " + defect.defect_id + " - attachment_thumbnail_url received:", defect.attachment_thumbnail_url);
    // Ensure elements are found before trying to use them
    if (popupImage && popupNoImage) {
        if (defect.attachment_thumbnail_url && defect.attachment_thumbnail_url.trim() !== '' && defect.attachment_thumbnail_url !== '#') {
            console.log("DEBUG_POPUP_JS: Defect ID " + defect.defect_id + " - Showing image. Setting src to:", defect.attachment_thumbnail_url);
            popupImage.src = defect.attachment_thumbnail_url;
            console.log("DEBUG_POPUP_JS: Defect ID " + defect.defect_id + " - popupImage.src is now:", popupImage.src);
            popupImage.classList.remove('hidden'); // Show image
            popupNoImage.classList.add('hidden');    // Hide no-image message
        } else {
            console.log("DEBUG_POPUP_JS: Defect ID " + defect.defect_id + " - Showing 'no image' message. attachment_thumbnail_url was:", defect.attachment_thumbnail_url);
            popupImage.src = '#'; // Clear src
            console.log("DEBUG_POPUP_JS: Defect ID " + defect.defect_id + " - popupImage.src is now:", popupImage.src);
            popupImage.classList.add('hidden');      // Hide image
            popupNoImage.classList.remove('hidden'); // Show no-image message
        }
    } else {
        console.error('Popup image or no-image element not found.');
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
