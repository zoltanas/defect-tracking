document.addEventListener('DOMContentLoaded', function() {
    const checklistContainer = document.querySelector('div.container > div.bg-white.p-6');

    if (!checklistContainer) {
        const fallbackContainer = document.querySelector('.container');
        if (fallbackContainer && fallbackContainer.querySelector('.checklist-item')) {
             console.warn('Using fallback checklist container. Check selector if issues arise.');
        } else {
            console.error('Checklist container not found. Script will not run correctly.');
            return;
        }
    }

    function addAttachmentToDOM(itemElement, attachment, isEditMode) {
        const targetModeDiv = itemElement.querySelector(isEditMode ? '.item-edit-mode' : '.item-view-mode');
        if (!targetModeDiv) {
            console.error(`Cannot find ${isEditMode ? 'edit' : 'view'} mode div in item:`, itemElement);
            return;
        }

        let attachmentsList;

        if (isEditMode) {
            // Edit Mode: Find or create attachments list container
            // Assumes structure: .item-edit-mode -> .mt-3 (parent for grid) -> .attachments-grid-edit (the grid)
            // The HTML for edit mode has a <p>Existing Attachments:</p> then the grid in a .mt-3 div.
            let parentContainerForGrid = targetModeDiv.querySelector('.mt-3 > p + .grid[class*="gap-3"], .mt-3:not(:has(p)) > .grid[class*="gap-3"]');
            if (parentContainerForGrid) { // If grid exists directly under .mt-3 (possibly after a <p>)
                 attachmentsList = parentContainerForGrid;
            } else {
                 // Try to find .mt-3 that should host the "Existing Attachments" <p> and the grid
                 let existingMt3 = targetModeDiv.querySelector('.mt-3');
                 if (!existingMt3) {
                    existingMt3 = document.createElement('div');
                    existingMt3.className = 'mt-3';
                    // Optionally add the <p> if it's always expected
                    const p = document.createElement('p');
                    p.className = 'block text-sm font-medium text-gray-600 mb-1';
                    p.textContent = 'Existing Attachments:';
                    existingMt3.appendChild(p);
                    targetModeDiv.appendChild(existingMt3); // Append to item-edit-mode
                 }
                 // Now create the grid
                attachmentsList = document.createElement('div');
                attachmentsList.className = 'mt-2 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3 attachments-grid-edit';
                existingMt3.appendChild(attachmentsList);
            }
        } else { // View Mode Logic
            const commentsAndAttachmentsAreaSelector = '.border-t.border-gray-200.mt-3.pt-3';
            let commentsAndAttachmentsArea = targetModeDiv.querySelector(commentsAndAttachmentsAreaSelector);

            if (!commentsAndAttachmentsArea) {
                commentsAndAttachmentsArea = document.createElement('div');
                commentsAndAttachmentsArea.className = 'border-t border-gray-200 mt-3 pt-3';
                targetModeDiv.appendChild(commentsAndAttachmentsArea);
            }

            const parentDivForGridSelector = '.checklist-item-view-attachments-parent';
            let parentDivForGrid = commentsAndAttachmentsArea.querySelector(parentDivForGridSelector);

            if (!parentDivForGrid) {
                parentDivForGrid = document.createElement('div');
                parentDivForGrid.className = 'pl-8 checklist-item-view-attachments-parent';
                if (commentsAndAttachmentsArea.querySelector('.checklist-item-comments-display')) {
                    parentDivForGrid.classList.add('mt-3');
                }
                commentsAndAttachmentsArea.appendChild(parentDivForGrid);
            }

            const attachmentsListSelector = '.attachments-grid-view';
            attachmentsList = parentDivForGrid.querySelector(attachmentsListSelector);

            if (!attachmentsList) {
                attachmentsList = document.createElement('div');
                attachmentsList.className = 'mt-2 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3 attachments-grid-view';
                parentDivForGrid.appendChild(attachmentsList);
            }
        }

        if (!attachmentsList) {
            console.error('Failed to find or create attachments list for item:', itemElement.dataset.itemId, 'Mode:', isEditMode ? 'edit' : 'view');
            return;
        }

        // Create and append the attachment div
        const attachmentDiv = document.createElement('div');
        attachmentDiv.dataset.attachmentId = attachment.id; // Universal attribute

        let thumbnailUrl = attachment.thumbnail_url;
        if (!thumbnailUrl && attachment.thumbnail_path) {
            thumbnailUrl = `/static/${attachment.thumbnail_path}`;
        }
        if (!thumbnailUrl) thumbnailUrl = 'placeholder.png'; // Fallback

        const img = document.createElement('img');
        img.src = thumbnailUrl;
        img.alt = `Thumbnail for attachment ${attachment.id}`;
        img.classList.add('max-w-full', 'max-h-full', 'object-contain');

        if (isEditMode) {
            attachmentDiv.className = 'relative group w-28 h-28 p-1 bg-gray-100 rounded-md flex items-center justify-center attachment-display'; // Add attachment-display

            const deleteButton = document.createElement('button');
            deleteButton.type = 'button';
            deleteButton.className = 'delete-attachment-btn absolute top-0 right-0 bg-red-500 text-white rounded-full p-1 text-xs opacity-0 group-hover:opacity-100';
            deleteButton.dataset.attachmentId = attachment.id;
            deleteButton.setAttribute('aria-label', 'Delete attachment');
            deleteButton.innerHTML = 'X';

            attachmentDiv.appendChild(img);
            attachmentDiv.appendChild(deleteButton);
        } else { // View Mode
            // Classes from HTML: w-28 h-28 p-1 bg-gray-100 rounded-md flex items-center justify-center cursor-pointer group hover:bg-gray-200 transition-colors duration-150 attachment-display
            attachmentDiv.className = 'w-28 h-28 p-1 bg-gray-100 rounded-md flex items-center justify-center cursor-pointer group hover:bg-gray-200 transition-colors duration-150 attachment-display';
            img.classList.add('pointer-events-none'); // From original code, seems correct
            attachmentDiv.role = 'button'; // From original code

            if (typeof openImagePopup === 'function') {
                let originalUrl = attachment.original_url;
                if (!originalUrl && attachment.file_path) {
                    originalUrl = `/static/${attachment.file_path}`;
                }
                // If originalUrl is still undefined/null, openImagePopup might need to handle it or show placeholder/error
                attachmentDiv.onclick = () => openImagePopup(originalUrl, attachment.id, '/draw/');
            } else {
                console.warn('openImagePopup function not found for view mode attachments.');
            }
            attachmentDiv.appendChild(img);
        }
        attachmentsList.appendChild(attachmentDiv);
    }

    checklistContainer.addEventListener('click', function(event) {
        const target = event.target;
        const checklistItem = target.closest('.checklist-item');
        if (!checklistItem) return;

        const itemId = checklistItem.dataset.itemId;

        if (target.classList.contains('edit-item-btn')) {
            toggleEditMode(checklistItem, true);
        } else if (target.classList.contains('save-item-btn')) {
            saveItemChanges(checklistItem);
        } else if (target.classList.contains('cancel-edit-btn')) {
            toggleEditMode(checklistItem, false);
        } else if (target.classList.contains('delete-attachment-btn')) {
            const attachmentId = target.dataset.attachmentId;
            const attachmentDiv = target.closest('.attachment-display');
            deleteAttachment(itemId, attachmentId, attachmentDiv, checklistItem);
        }
    });

    checklistContainer.addEventListener('change', function(event) {
        const target = event.target;
        const checklistItem = target.closest('.checklist-item');
        if (!checklistItem) return;

        const itemId = checklistItem.dataset.itemId;

        if (target.matches('input[type="checkbox"][name^="item_' + itemId + '_checked"]')) {
            updateCheckboxStatus(itemId, checklistItem, target);
        }
    });

    function toggleEditMode(checklistItem, isEditMode) {
        const viewModeDiv = checklistItem.querySelector('.item-view-mode');
        const editModeDiv = checklistItem.querySelector('.item-edit-mode');

        if (!viewModeDiv || !editModeDiv) {
            console.error('View or Edit mode div not found in checklist item:', checklistItem);
            return;
        }

        if (isEditMode) {
            viewModeDiv.classList.add('hidden');
            editModeDiv.classList.remove('hidden');
            checklistItem.dataset.mode = 'edit';

            const viewCheckbox = viewModeDiv.querySelector('input[type="checkbox"][name$="_view"]');
            const editCheckbox = editModeDiv.querySelector('input[type="checkbox"][name$="_edit"]');
            if (viewCheckbox && editCheckbox) {
                editCheckbox.checked = viewCheckbox.checked;
            }
            const commentsView = viewModeDiv.querySelector('.item-comments-view');
            const commentsEdit = editModeDiv.querySelector('textarea[name$="_comments_edit"]');
            if (commentsView && commentsEdit) {
                commentsEdit.value = commentsView.textContent.trim();
            }

        } else {
            editModeDiv.classList.add('hidden');
            viewModeDiv.classList.remove('hidden');
            checklistItem.dataset.mode = 'view';

            const fileInput = editModeDiv.querySelector('input[type="file"]');
            if (fileInput) {
                fileInput.value = '';
            }
        }
    }

    async function updateCheckboxStatus(itemId, checklistItem, checkboxElement) {
        const isChecked = checkboxElement.checked;

        const csrfToken = window.csrfTokenGlobal;
        if (!csrfToken) {
            console.error('JS: window.csrfTokenGlobal not found or empty before updating checkbox status. Aborting.');
            alert('Error: CSRF token (global) not found. Please refresh the page and try again.');
            // Revert checkbox optimistic update
            if (checkboxElement) {
                checkboxElement.checked = !isChecked;
            }
            return;
        }

        const fetchOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ is_checked: isChecked })
        };
        console.log(`JS: updateCheckboxStatus for item ${itemId} - Fetching URL: /checklist_item/${itemId}/update_status`);
        // console.log(`JS: updateCheckboxStatus for item ${itemId} - Fetch Options:`, JSON.stringify(fetchOptions, null, 2));

        fetch(`/checklist_item/${itemId}/update_status`, fetchOptions)
            .then(response => {
                if (!response.ok) {
                    return response.json()
                        .catch(() => response.text())
                        .then(errorBody => {
                            let errorMessage = `Failed to update checkbox status (${response.status})`;
                            if (typeof errorBody === 'object' && errorBody !== null && errorBody.message) {
                                errorMessage = errorBody.message;
                            } else if (typeof errorBody === 'string' && errorBody.trim() !== '') {
                                errorMessage = errorBody;
                            }
                            console.error(`JS: Server error for item ${itemId}: ${errorMessage}. Status: ${response.status}. Full response object:`, response);
                            throw new Error(errorMessage);
                        });
                }
                return response.json();
            })
            .then(result => {
                // console.log(`JS: Server response object for item ${itemId} (SUCCESS):`, result);
                if (result && typeof result.new_status !== 'undefined') {
                    checkboxElement.checked = result.new_status;
                    const currentMode = checklistItem.dataset.mode;
                    const otherCheckboxSelector = currentMode === 'view' ?
                        '.item-edit-mode input[type="checkbox"][name$="_edit"]' :
                        '.item-view-mode input[type="checkbox"][name$="_view"]';
                    const otherCheckbox = checklistItem.querySelector(otherCheckboxSelector);
                    if (otherCheckbox) {
                        otherCheckbox.checked = result.new_status;
                    }
                } else {
                    console.warn(`JS: Server response for item ${itemId} did not contain new_status or result is unexpected:`, result);
                }
            })
            .catch(error => {
                console.error(`JS: Error updating checkbox status for item ${itemId} (in outer catch):`, error.message);
                if (checkboxElement) {
                     checkboxElement.checked = !isChecked;
                }
            });
    }

    async function saveItemChanges(checklistItem) {
        const itemId = checklistItem.dataset.itemId;
        const editModeDiv = checklistItem.querySelector('.item-edit-mode');
        const viewModeDiv = checklistItem.querySelector('.item-view-mode');

        const commentsTextarea = editModeDiv.querySelector('textarea[name$="_comments_edit"]');
        const comments = commentsTextarea.value;
        const photosInput = editModeDiv.querySelector('input[type="file"][name$="_photos_edit"]');
        const files = photosInput.files;

        const editCheckbox = editModeDiv.querySelector('input[type="checkbox"][name$="_edit"]');
        if (editCheckbox && editCheckbox.matches(':indeterminate') === false) {
            // console.log(`JS: Ensuring checkbox state for item ${itemId} is saved as part of saveItemChanges.`);
            await updateCheckboxStatus(itemId, checklistItem, editCheckbox);
        }

        let saveOk = true;

        try {
            const csrfTokenComments = window.csrfTokenGlobal;
            if (!csrfTokenComments) {
                console.error('JS: window.csrfTokenGlobal not found or empty before saving comments. Aborting save.');
                alert('Error: CSRF token (global) not found for saving comments. Please refresh and try again.');
                // Potentially indicate save failure to the user without toggling edit mode
                return; // Abort the save operation
            }
            const commentResponse = await fetch(`/checklist_item/${itemId}/update_comments`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfTokenComments
                },
                body: JSON.stringify({ comments: comments })
            });
            if (!commentResponse.ok) {
                const errorData = await commentResponse.json().catch(() => ({}));
                throw new Error(errorData.error || `Failed to save comments (${commentResponse.status})`);
            }
            const commentResult = await commentResponse.json();

            const commentsViewDiv = viewModeDiv.querySelector('.checklist-item-comments-display');
            if (commentsViewDiv) commentsViewDiv.textContent = commentResult.new_comments || comments;

        } catch (error) {
            console.error('Error saving comments:', error.message);
            saveOk = false;
        }

        if (files.length > 0 && saveOk) {
            const formData = new FormData();
            for (const file of files) {
                formData.append('photos', file);
            }

            const csrfTokenPhotos = window.csrfTokenGlobal;
            if (!csrfTokenPhotos) {
                console.error('JS: window.csrfTokenGlobal not found or empty before uploading photos. Aborting photo upload.');
                alert('Error: CSRF token (global) not found for uploading photos. Please refresh and try again.');
                saveOk = false; // Indicate that the overall save is not fully successful
            }

            if (saveOk) { // Proceed only if CSRF token was found (and other conditions met)
                try {
                    const photoResponse = await fetch(`/checklist_item/${itemId}/add_attachment`, {
                        method: 'POST',
                        headers: {
                            'X-CSRFToken': csrfTokenPhotos
                        },
                        body: formData
                    });
                    if (!photoResponse.ok) {
                    const errorData = await photoResponse.json().catch(() => ({}));
                    throw new Error(errorData.error || `Failed to upload photos (${photoResponse.status})`);
                }
                const newAttachmentsResult = await photoResponse.json();

                if (newAttachmentsResult.attachments && Array.isArray(newAttachmentsResult.attachments)) {
                    newAttachmentsResult.attachments.forEach(att => {
                       addAttachmentToDOM(checklistItem, att, false);
                       addAttachmentToDOM(checklistItem, att, true);
                    });
                }
                photosInput.value = '';
            } catch (error) {
                console.error('Error uploading photos:', error.message);
                saveOk = false;
            }
        } // Closing the if(saveOk) for photo upload
    }

        if (saveOk) {
            toggleEditMode(checklistItem, false);
        }
    }

    async function deleteAttachment(itemId, attachmentId, attachmentElement, checklistItem) {
        if (!confirm('Are you sure you want to delete this attachment?')) return;

        const csrfToken = window.csrfTokenGlobal;
        if (!csrfToken) {
            console.error('JS: window.csrfTokenGlobal not found or empty immediately before deleting attachment. Aborting.');
            alert('Error: CSRF token (global) not found. Please refresh the page and try again.');
            return;
        }

        try {
            const response = await fetch(`/checklist_item/${itemId}/delete_attachment/${attachmentId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                }
            });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `Failed to delete attachment (${response.status})`);
            }
            await response.json();

            if (attachmentElement) {
                attachmentElement.remove();
                if (checklistItem) {
                    const otherModeAttachment = checklistItem.querySelector(`.attachment-display[data-attachment-id="${attachmentId}"]`);
                    if (otherModeAttachment) otherModeAttachment.remove();
                }
            }
        } catch (error) {
            console.error('Error deleting attachment:', error.message);
        }
    }
});
