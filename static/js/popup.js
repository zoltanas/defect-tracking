// Function to open the image popup
function openImagePopup(imageSrc, attachmentId, editUrlBase) {
    const imagePopupModal = document.getElementById('imagePopupModal');
    const popupImage = document.getElementById('popupImage');
    const editImageButton = document.getElementById('editImageButton');

    if (imagePopupModal && popupImage && editImageButton) {
        popupImage.src = imageSrc;
        editImageButton.href = editUrlBase + attachmentId;
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
    const cancelImagePopupButton = document.getElementById('cancelImagePopupButton');

    if (closeImagePopupButton) {
        closeImagePopupButton.addEventListener('click', closeImagePopup);
    }

    if (cancelImagePopupButton) {
        cancelImagePopupButton.addEventListener('click', closeImagePopup);
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