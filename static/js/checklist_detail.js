document.addEventListener('DOMContentLoaded', function() {
    let csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    if (!csrfToken) {
        console.error('JS: CSRF token not found or is empty. AJAX POST/DELETE calls will likely fail due to missing CSRF protection.');
    }
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

    // if (!csrfToken) { // This check is now done above and includes an error log
    //     console.warn('CSRF token not found in meta tag. AJAX requests will likely fail.');
    // }

    function addAttachmentToDOM(itemElement, attachment, isEditMode) {
        const modeClass = isEditMode ? '.item-edit-mode' : '.item-view-mode';
        const targetModeDiv = itemElement.querySelector(modeClass);
        if (!targetModeDiv) {
            console.error(`Cannot find ${modeClass} in item:`, itemElement);
            return;
        }

        let attachmentsList = targetModeDiv.querySelector('.grid[class*="gap-3"]');
        if (!attachmentsList) {
            let baseAttachmentContainer = isEditMode ?
                targetModeDiv.querySelector('.mt-3 > .grid[class*="gap-3"]') :
                targetModeDiv.querySelector('.mt-3.pl-8 > .grid[class*="gap-3"]');

            if (!baseAttachmentContainer) {
                // console.warn('Specific attachment grid not found, creating one for item ' + itemElement.dataset.itemId);
                const parentDivForGrid = isEditMode ? targetModeDiv.querySelector('.mt-3') : targetModeDiv.querySelector('.mt-3.pl-8');
                if (parentDivForGrid) {
                    baseAttachmentContainer = document.createElement('div');
                    baseAttachmentContainer.className = 'mt-2 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3 attachments-list';
                    parentDivForGrid.appendChild(baseAttachmentContainer);
                } else {
                    console.error('Parent div for creating attachment grid not found in', targetModeDiv);
                    return;
                }
            }
            attachmentsList = baseAttachmentContainer;
        }

        const attachmentDiv = document.createElement('div');
        attachmentDiv.classList.add('relative', 'group', 'w-28', 'h-28', 'p-1', 'bg-gray-100', 'rounded-md', 'flex', 'items-center', 'justify-center', 'attachment-display');
        attachmentDiv.dataset.attachmentId = attachment.id;

        let thumbnailUrl = attachment.thumbnail_url;
        if (!thumbnailUrl && attachment.thumbnail_path) {
            thumbnailUrl = `/static/${attachment.thumbnail_path}`;
        }
        if (!thumbnailUrl) thumbnailUrl = 'placeholder.png';

        const img = document.createElement('img');
        img.src = thumbnailUrl;
        img.alt = `Thumbnail for attachment ${attachment.id}`;
        img.classList.add('max-w-full', 'max-h-full', 'object-contain');
        if (!isEditMode) {
            img.classList.add('pointer-events-none');
            attachmentDiv.role = 'button';
            attachmentDiv.classList.add('cursor-pointer', 'group', 'hover:bg-gray-200', 'transition-colors', 'duration-150');
            if (typeof openImagePopup === 'function') {
                attachmentDiv.onclick = () => openImagePopup(attachment.original_url || `/static/${attachment.file_path}`, attachment.id, '/draw/');
            } else {
                console.warn('openImagePopup function not found for view mode attachments.');
            }
        }
        attachmentDiv.appendChild(img);

        if (isEditMode) {
            const deleteButton = document.createElement('button');
            deleteButton.type = 'button';
            deleteButton.classList.add('delete-attachment-btn', 'absolute', 'top-0', 'right-0', 'bg-red-500', 'text-white', 'rounded-full', 'p-1', 'text-xs', 'opacity-0', 'group-hover:opacity-100');
            deleteButton.dataset.attachmentId = attachment.id;
            deleteButton.setAttribute('aria-label', 'Delete attachment');
            deleteButton.innerHTML = 'X';
            attachmentDiv.appendChild(deleteButton);
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
            const commentResponse = await fetch(`/checklist_item/${itemId}/update_comments`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ comments: comments })
            });
            if (!commentResponse.ok) {
                const errorData = await commentResponse.json().catch(() => ({}));
                throw new Error(errorData.error || `Failed to save comments (${commentResponse.status})`);
            }
            const commentResult = await commentResponse.json();

            const commentsViewDiv = viewModeDiv.querySelector('.item-comments-view');
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
            try {
                const photoResponse = await fetch(`/checklist_item/${itemId}/add_attachment`, {
                    method: 'POST',
                    headers: {
                        'X-CSRFToken': csrfToken
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
        }

        if (saveOk) {
            toggleEditMode(checklistItem, false);
        }
    }

    async function deleteAttachment(itemId, attachmentId, attachmentElement, checklistItem) {
        if (!confirm('Are you sure you want to delete this attachment?')) return;

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
