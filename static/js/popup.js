// Function to open the image popup
function openImagePopup(imageSrc, attachmentId, editUrlBase) {
    console.log('Opening image popup with imageSrc:', imageSrc);
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

// PDF Popup Functionality
let pdfDoc = null,
    pageNum = 1,
    pageRendering = false,
    pageNumPending = null,
    currentScale = 1.0, // Initial scale
    pdfCanvasGlobal = null, // Renamed to avoid conflict if 'pdfCanvas' is too generic
    pdfCtxGlobal = null; // Renamed

function openPdfPopup(pdfUrl) {
    const modal = document.getElementById('pdfViewerModal');
    pdfCanvasGlobal = document.getElementById('pdfCanvas'); // Ensure this ID matches your modal's canvas

    if (!modal || !pdfCanvasGlobal) {
        console.error('PDF Modal or Canvas element not found!');
        return;
    }

    // Reset state for new PDF
    pdfDoc = null;
    pageNum = 1;
    pageRendering = false;
    pageNumPending = null;
    currentScale = 1.0; // Reset to initial scale

    modal.classList.remove('hidden');
    modal.classList.add('flex'); // Assuming flex is used for visibility

    document.getElementById('closePdfModalButton').onclick = () => {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
        if (pdfDoc) { // Clean up PDF.js resources if any
            pdfDoc.destroy();
            pdfDoc = null;
        }
    };

    // Ensure PDF.js worker is configured (it should be set in the HTML template)
    if (!pdfjsLib.GlobalWorkerOptions.workerSrc) {
        console.error("PDF.js workerSrc is not set. Please set pdfjsLib.GlobalWorkerOptions.workerSrc.");
        // Potentially set it here if a global variable for the path is available, e.g.
        // pdfjsLib.GlobalWorkerOptions.workerSrc = window.pdfWorkerSrc; // if window.pdfWorkerSrc is set in template
    }

    pdfjsLib.getDocument(pdfUrl).promise.then(doc => {
        pdfDoc = doc;
        document.getElementById('pdfPageCount').textContent = pdfDoc.numPages;
        renderPdfPage(pageNum, currentScale);
    }).catch(error => {
        console.error('Error loading PDF:', error);
        alert('Error loading PDF: ' + error.message);
        modal.classList.add('hidden'); // Hide modal on error
        modal.classList.remove('flex');
    });

    document.getElementById('pdfPrevPage').onclick = onPrevPage;
    document.getElementById('pdfNextPage').onclick = onNextPage;
    document.getElementById('pdfZoomIn').onclick = onZoomIn;
    document.getElementById('pdfZoomOut').onclick = onZoomOut;
}

function renderPdfPage(num, scale) {
    if (!pdfDoc) {
        return; // PDF not loaded yet
    }
    pageRendering = true;
    pdfDoc.getPage(num).then(page => {
        const viewport = page.getViewport({ scale: scale });
        pdfCanvasGlobal.height = viewport.height;
        pdfCanvasGlobal.width = viewport.width;
        pdfCtxGlobal = pdfCanvasGlobal.getContext('2d');

        const renderContext = {
            canvasContext: pdfCtxGlobal,
            viewport: viewport
        };
        const renderTask = page.render(renderContext);
        renderTask.promise.then(() => {
            pageRendering = false;
            if (pageNumPending !== null) {
                renderPdfPage(pageNumPending, currentScale); // Use currentScale for pending page
                pageNumPending = null;
            }
        }).catch(error => {
            console.error('Error rendering page:', error);
            pageRendering = false; // Reset flag on error
        });
    });
    document.getElementById('pdfPageNum').textContent = num;
}

function queueRenderPage(num) {
    if (pageRendering) {
        pageNumPending = num;
    } else {
        renderPdfPage(num, currentScale);
    }
}

function onPrevPage() {
    if (!pdfDoc || pageNum <= 1) return;
    pageNum--;
    queueRenderPage(pageNum);
}

function onNextPage() {
    if (!pdfDoc || pageNum >= pdfDoc.numPages) return;
    pageNum++;
    queueRenderPage(pageNum);
}

function onZoomIn() {
    currentScale += 0.2;
    renderPdfPage(pageNum, currentScale);
}

function onZoomOut() {
    if (currentScale <= 0.2) return; // Min scale
    currentScale -= 0.2;
    renderPdfPage(pageNum, currentScale);
}
