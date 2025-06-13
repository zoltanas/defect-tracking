import sys
import re

# Helper to find a user row and then check for revoke button for a specific PA_ID
def check_user_row_and_revoke_button(html_content, username_in_row, pa_id_to_check_revoke, expect_revoke_button):
    # Ensure all prints in this function use flush=True for reliable output redirection
    revoke_form_pattern = f'action="/revoke_access/{pa_id_to_check_revoke}"'
    is_revoke_button_present = revoke_form_pattern in html_content

    print(f"    - User in row (for context): '{username_in_row}', Revoke button for PA_ID {pa_id_to_check_revoke}:", flush=True)
    print(f"      Searching for revoke form: {revoke_form_pattern}", flush=True)
    print(f"      Form present: {is_revoke_button_present}, Expected: {expect_revoke_button}", flush=True)
    if is_revoke_button_present == expect_revoke_button:
        print("      Result: PASS", flush=True)
        return True
    else:
        print("      Result: FAIL", flush=True)
        return False

def check_user_presence_in_table(html_content, username_to_find, project_name_to_find, expect_present):
    pattern = re.compile(rf'<tr>.*?<td.*?>\s*{re.escape(username_to_find)}\s*</td>.*?<td.*?>\s*{re.escape(project_name_to_find)}\s*</td>.*?</tr>', re.DOTALL)
    is_present = bool(pattern.search(html_content))

    print(f"    - User '{username_to_find}' on Project '{project_name_to_find}':", flush=True)
    print(f"      Present in table: {is_present}, Expected: {expect_present}", flush=True)
    if is_present == expect_present: # Corrected logic here
        print("      Result: PASS", flush=True)
        return True
    else:
        print("      Result: FAIL", flush=True)
        return False

def main():
    if len(sys.argv) < 7:
        print("Usage: python analyze_manage_access_page.py <current_username> <layout_html_path> <manage_access_html_path> <pa_id_otheradmin_pA> ...", flush=True)
        sys.exit(1)

    current_username = sys.argv[1] # This is the username of the logged-in user for the test
    layout_html_path = sys.argv[2]
    manage_access_html_path = sys.argv[3]

    pa_id_map = {
        "otheradmin_ProjectAlpha_MA": int(sys.argv[4]),
        "testexpert_ProjectAlpha_MA": int(sys.argv[5]),
        "testexpert_ProjectBeta_MA": int(sys.argv[6]),
        "testcontractor_ProjectBeta_MA": int(sys.argv[7]),
        "testsupervisor_ProjectGamma_MA": int(sys.argv[8]),
        "testuser1_ProjectAlpha_MA": int(sys.argv[9]),
        "testuser2_ProjectBeta_MA": int(sys.argv[10]),
        "testuser3_ProjectGamma_MA": int(sys.argv[11]),
    }

    print(f"\n--- Analysis for Logged-in User: {current_username} ---", flush=True)

    try:
        with open(layout_html_path, 'r', encoding='utf-8') as f:
            layout_content = f.read()
    except FileNotFoundError:
        print(f"ERROR: Layout HTML file '{layout_html_path}' not found.", flush=True)
        return

    try:
        with open(manage_access_html_path, 'r', encoding='utf-8') as f:
            manage_access_content = f.read()
    except FileNotFoundError:
        print(f"ERROR: Manage Access HTML file '{manage_access_html_path}' not found.", flush=True)
        return

    print("\n  1. Navigation Link Text:", flush=True)
    nav_link_pattern_admin_text = r'>\s*Manage User Access\s*</a>'
    nav_link_pattern_other_text = r'>\s*Projects user list\s*</a>'

    is_admin_nav_text_present = bool(re.search(nav_link_pattern_admin_text, layout_content))
    is_other_nav_text_present = bool(re.search(nav_link_pattern_other_text, layout_content))

    # Determine the actual global role of current_username for correct expectation setting
    # This mapping should match USER_CONFIG in the setup script
    # For simplicity in analysis script, we'll hardcode based on the usernames used in the test plan
    actual_user_global_role = ""
    if current_username == 'testadmin' or current_username == 'otheradmin':
        actual_user_global_role = 'admin'
    elif current_username == 'testexpert' or current_username == 'testuser2':
        actual_user_global_role = 'expert'
    elif current_username == 'testcontractor' or current_username == 'testuser1' or current_username == 'testuser3':
        actual_user_global_role = 'contractor'
    elif current_username == 'testsupervisor':
        actual_user_global_role = 'supervisor'


    if actual_user_global_role == 'admin':
        print(f"    Nav link text found ('Manage User Access'): {is_admin_nav_text_present}, Expected: True", flush=True)
        if is_admin_nav_text_present and not is_other_nav_text_present :
             print("    Result: PASS", flush=True)
        else:
            print(f"    Result: FAIL (Admin text present: {is_admin_nav_text_present}, Other text present: {is_other_nav_text_present})", flush=True)
    elif actual_user_global_role in ['expert', 'contractor', 'supervisor']:
        print(f"    Nav link text found ('Projects user list'): {is_other_nav_text_present}, Expected: True", flush=True)
        if is_other_nav_text_present and not is_admin_nav_text_present:
            print("    Result: PASS", flush=True)
        else:
            print(f"    Result: FAIL (Other text present: {is_other_nav_text_present}, Admin text present: {is_admin_nav_text_present})", flush=True)
    else:
        print(f"    Warning: Could not determine expected nav link text for user '{current_username}'.", flush=True)


    print("\n  2. Section Visibility in /manage_access:", flush=True)
    grant_section_visible = "Grant Access to Existing User" in manage_access_content
    invite_section_visible = "Invite New User" in manage_access_content

    # Determine if the current user (whose view is being tested) is an admin
    # This should align with the `is_admin_view` variable in the template.
    current_user_is_admin_for_view = (actual_user_global_role == 'admin')

    print(f"    - 'Grant Access' section visible: {grant_section_visible}, Expected: {current_user_is_admin_for_view}", flush=True)
    if grant_section_visible == current_user_is_admin_for_view: print("      Result: PASS", flush=True)
    else: print("      Result: FAIL", flush=True)

    print(f"    - 'Invite New User' section visible: {invite_section_visible}, Expected: {current_user_is_admin_for_view}", flush=True)
    if invite_section_visible == current_user_is_admin_for_view: print("      Result: PASS", flush=True)
    else: print("      Result: FAIL", flush=True)

    print("\n  3. 'Current User Access' Table:", flush=True)
    table_visible = "Current User Access</h2>" in manage_access_content
    print(f"    - Table section visible: {table_visible}, Expected: True", flush=True) # Table should always be visible
    if not table_visible: print("      Result: FAIL (Table heading not found)", flush=True)
    else: print("      Result: PASS (Table heading found, content checks below)", flush=True)

    if current_username == 'testadmin': # Logged in as testadmin
        print("    Revoke Button Checks (as testadmin):", flush=True)
        check_user_row_and_revoke_button(manage_access_content, "otheradmin", pa_id_map["otheradmin_ProjectAlpha_MA"], False)
        check_user_row_and_revoke_button(manage_access_content, "testexpert", pa_id_map["testexpert_ProjectAlpha_MA"], True)
        check_user_row_and_revoke_button(manage_access_content, "testexpert", pa_id_map["testexpert_ProjectBeta_MA"], True)
        check_user_row_and_revoke_button(manage_access_content, "testuser1", pa_id_map["testuser1_ProjectAlpha_MA"], True)
        check_user_row_and_revoke_button(manage_access_content, "testcontractor", pa_id_map["testcontractor_ProjectBeta_MA"], True)
        check_user_row_and_revoke_button(manage_access_content, "testuser2", pa_id_map["testuser2_ProjectBeta_MA"], True)
        check_user_row_and_revoke_button(manage_access_content, "testsupervisor", pa_id_map["testsupervisor_ProjectGamma_MA"], True)
        check_user_row_and_revoke_button(manage_access_content, "testuser3", pa_id_map["testuser3_ProjectGamma_MA"], True)

        print("    User Presence Checks (as testadmin):", flush=True)
        check_user_presence_in_table(manage_access_content, "otheradmin", "ProjectAlpha_MA", True)
        check_user_presence_in_table(manage_access_content, "testexpert", "ProjectAlpha_MA", True)
        check_user_presence_in_table(manage_access_content, "testexpert", "ProjectBeta_MA", True)
        check_user_presence_in_table(manage_access_content, "testuser1", "ProjectAlpha_MA", True)
        check_user_presence_in_table(manage_access_content, "testcontractor", "ProjectBeta_MA", True)
        check_user_presence_in_table(manage_access_content, "testuser2", "ProjectBeta_MA", True)
        check_user_presence_in_table(manage_access_content, "testsupervisor", "ProjectGamma_MA", True)
        check_user_presence_in_table(manage_access_content, "testuser3", "ProjectGamma_MA", True)

    elif current_username == 'testexpert':
        print("    Revoke Button Checks (as testexpert): All HIDDEN", flush=True)
        # Check a few representative cases for non-admins (all revoke buttons should be hidden)
        check_user_row_and_revoke_button(manage_access_content, "otheradmin", pa_id_map["otheradmin_ProjectAlpha_MA"], False)
        check_user_row_and_revoke_button(manage_access_content, "testuser1", pa_id_map["testuser1_ProjectAlpha_MA"], False)

        print("    User Presence Checks (as testexpert, sees users on ProjectAlpha_MA & ProjectBeta_MA):", flush=True)
        check_user_presence_in_table(manage_access_content, "testadmin", "ProjectAlpha_MA", True)
        check_user_presence_in_table(manage_access_content, "testadmin", "ProjectBeta_MA", True)
        check_user_presence_in_table(manage_access_content, "otheradmin", "ProjectAlpha_MA", True)
        check_user_presence_in_table(manage_access_content, "testuser1", "ProjectAlpha_MA", True)
        check_user_presence_in_table(manage_access_content, "testcontractor", "ProjectBeta_MA", True)
        check_user_presence_in_table(manage_access_content, "testuser2", "ProjectBeta_MA", True)
        check_user_presence_in_table(manage_access_content, "testsupervisor", "ProjectGamma_MA", False)
        check_user_presence_in_table(manage_access_content, "testuser3", "ProjectGamma_MA", False)

    elif current_username == 'testcontractor':
        print("    Revoke Button Checks (as testcontractor): All HIDDEN", flush=True)
        check_user_row_and_revoke_button(manage_access_content, "testexpert", pa_id_map["testexpert_ProjectBeta_MA"], False)
        check_user_row_and_revoke_button(manage_access_content, "testuser2", pa_id_map["testuser2_ProjectBeta_MA"], False)

        print("    User Presence Checks (as testcontractor, sees users on ProjectBeta_MA):", flush=True)
        check_user_presence_in_table(manage_access_content, "testadmin", "ProjectBeta_MA", True)
        check_user_presence_in_table(manage_access_content, "testexpert", "ProjectBeta_MA", True)
        check_user_presence_in_table(manage_access_content, "testuser2", "ProjectBeta_MA", True)
        check_user_presence_in_table(manage_access_content, "testadmin", "ProjectAlpha_MA", False)
        check_user_presence_in_table(manage_access_content, "testuser1", "ProjectAlpha_MA", False)
        check_user_presence_in_table(manage_access_content, "testsupervisor", "ProjectGamma_MA", False)

    elif current_username == 'testsupervisor':
        print("    Revoke Button Checks (as testsupervisor): All HIDDEN", flush=True)
        check_user_row_and_revoke_button(manage_access_content, "testadmin", pa_id_map["testuser3_ProjectGamma_MA"], False) # Using a PA_ID from a user on Gamma
        check_user_row_and_revoke_button(manage_access_content, "testuser3", pa_id_map["testuser3_ProjectGamma_MA"], False)

        print("    User Presence Checks (as testsupervisor, sees users on ProjectGamma_MA):", flush=True)
        check_user_presence_in_table(manage_access_content, "testadmin", "ProjectGamma_MA", True)
        check_user_presence_in_table(manage_access_content, "testuser3", "ProjectGamma_MA", True)
        check_user_presence_in_table(manage_access_content, "testadmin", "ProjectAlpha_MA", False)
        check_user_presence_in_table(manage_access_content, "testexpert", "ProjectBeta_MA", False)

if __name__ == "__main__":
    main()
