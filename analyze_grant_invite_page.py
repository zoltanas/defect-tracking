import sys
import re

def print_test_result(condition, test_name):
    if condition:
        print(f"      {test_name}: PASS", flush=True)
    else:
        print(f"      {test_name}: FAIL", flush=True)

def main():
    if len(sys.argv) < 3:
        print("Usage: python analyze_grant_invite_page.py <current_username_performing_view> <manage_access_html_path>", flush=True)
        sys.exit(1)

    current_username = sys.argv[1]
    manage_access_html_path = sys.argv[2]

    print(f"\n--- Analysis for User: {current_username} viewing /manage_access ---", flush=True)

    try:
        with open(manage_access_html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
    except FileNotFoundError:
        print(f"ERROR: Manage Access HTML file '{manage_access_html_path}' not found.", flush=True)
        return

    # Determine the global role of the current_username for expectation setting
    # This is a simplified mapping based on the test plan's user setup.
    is_admin_viewer = (current_username == 'testadmin')

    # Test II.A.1 (Admin View): Invite New User section UI
    if is_admin_viewer:
        print("  II.A.1 'Invite New User' Section UI (as Admin):", flush=True)
        invite_role_select_present = '<select name="role" id="invite_role"' in html_content
        print_test_result(invite_role_select_present, "Invite role select dropdown is present")

        if invite_role_select_present:
            admin_option_in_invite = '<option value="admin">Admin</option>' in html_content
            print_test_result(not admin_option_in_invite, "Admin option NOT in invite role dropdown")

            expert_option_in_invite = '<option value="expert">Expert</option>' in html_content
            print_test_result(expert_option_in_invite, "Expert option IS in invite role dropdown")

            contractor_option_in_invite = '<option value="contractor">Contractor</option>' in html_content
            print_test_result(contractor_option_in_invite, "Contractor option IS in invite role dropdown")

            supervisor_option_in_invite = '<option value="Technical supervisor">Technical supervisor</option>' in html_content
            print_test_result(supervisor_option_in_invite, "Supervisor option IS in invite role dropdown")

    # Test II.B.1 (Admin View): Grant Access to Existing User section UI
    if is_admin_viewer:
        print("  II.B.1 'Grant Access to Existing User' Section UI (as Admin):", flush=True)
        # The whole role div should be missing.
        # The div has class="mb-6" and contains label for="role"
        grant_access_role_div_pattern = r'<div class="mb-6">\s*<label for="role"'
        is_grant_role_div_present = bool(re.search(grant_access_role_div_pattern, html_content))
        print_test_result(not is_grant_role_div_present, "Role selection div NOT present in Grant Access form")

    # Test III (Non-Admin View): Section Visibility
    if not is_admin_viewer: # e.g., testviewer_expert
        print(f"  III. Non-Admin View ({current_username}): Section Visibility", flush=True)
        grant_section_heading = "Grant Access to Existing User"
        invite_section_heading = "Invite New User"

        is_grant_section_present = grant_section_heading in html_content
        is_invite_section_present = invite_section_heading in html_content

        print_test_result(not is_grant_section_present, "'Grant Access' section HIDDEN")
        print_test_result(not is_invite_section_present, "'Invite New User' section HIDDEN")

if __name__ == "__main__":
    main()
