// Function to open the image popup
function openImagePopup(imageSrc, attachmentId, editUrlBase) {
    const imagePopupModal = document.getElementById('imagePopupModal');
    const popupImage = document.getElementById('popupImage');
    const editImageButton = document.getElementById('editImageButton');
    const deleteImageButton = document.getElementById('deleteImageButton');

    if (imagePopupModal && popupImage && editImageButton && deleteImageButton) {
        popupImage.src = imageSrc;
        editImageButton.href = editUrlBase + attachmentId;
        deleteImageButton.dataset.attachmentId = attachmentId; // Store attachmentId on the delete button
        imagePopupModal.classList.remove('hidden');
        imagePopupModal.classList.add('flex'); // Assuming flex is used for visible modals
    }
}

// Function to close the image popup
function closeImagePopup() {
    const imagePopupModal = document.getElementById('imagePopupModal');
    if (imagePopupModal) {
        imagePopupModal.classList.add('hidden');
        imagePopupModal.classList.remove('flex');
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    const imagePopupModal = document.getElementById('imagePopupModal');
    const closeImagePopupButton = document.getElementById('closeImagePopupButton');
    // Button with ID "cancelImagePopupButton" was changed to "deleteImageButton"
    // const cancelImagePopupButton = document.getElementById('cancelImagePopupButton');
    const deleteImageButton = document.getElementById('deleteImageButton');

    if (closeImagePopupButton) {
        closeImagePopupButton.addEventListener('click', closeImagePopup);
    }

    // if (cancelImagePopupButton) { // This button is now deleteImageButton
    //     cancelImagePopupButton.addEventListener('click', closeImagePopup);
    // }

    if (deleteImageButton) {
        deleteImageButton.addEventListener('click', function() {
            const attachmentId = this.dataset.attachmentId;
            if (!attachmentId) {
                alert('Error: Attachment ID not found.');
                return;
            }

            if (confirm('Are you sure you want to delete this image? This action cannot be undone.')) {
                // Assume csrfToken is globally available (e.g., set in a script tag in layout.html)
                if (typeof csrfToken === 'undefined') {
                    console.error('CSRF token is not defined. Make sure it is set globally.');
                    alert('Error: CSRF token not found. Cannot proceed with deletion.');
                    return;
                }

                fetch(`/delete_image/${attachmentId}`, {
                    method: 'DELETE',
                    headers: {
                        'X-CSRFToken': csrfToken
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        alert(data.message || 'Image deleted successfully.');
                        closeImagePopup();
                        location.reload(); // Reload to reflect changes
                    } else {
                        alert('Error: ' + (data.message || 'Could not delete image.'));
                    }
                })
                .catch(error => {
                    console.error('Error deleting image:', error);
                    alert('An error occurred while trying to delete the image.');
                });
            }
        });
    }

    if (imagePopupModal) {
        // Close popup if background is clicked
        imagePopupModal.addEventListener('click', (event) => {
            if (event.target === imagePopupModal) {
                closeImagePopup();
            }
        });
    }
});