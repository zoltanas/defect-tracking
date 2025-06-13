import sys

def analyze(html_file_path, pa_id_admin1_self, pa_id_admin2, pa_id_expert):
    try:
        with open(html_file_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
    except FileNotFoundError:
        print(f"ERROR: HTML file '{html_file_path}' not found.")
        return

    # Construct search patterns for the action attribute of the form
    # Example: action="/revoke_access/3"
    # Using double quotes in pattern as url_for usually generates them, but check actual HTML output
    # For robustness, can make it ignore quote type or check for both ' and " around the URL.
    # For now, assuming double quotes as per typical url_for output.

    # Pattern for Scenario 1 (Admin viewing another Admin - testadmin2)
    # Expected: Form NOT present
    revoke_form_admin2_pattern = f'action="/revoke_access/{pa_id_admin2}"'
    is_form_admin2_present = revoke_form_admin2_pattern in html_content
    print(f"\n--- Scenario 1: Admin (current_user) viewing another Admin (testadmin2, PA_ID: {pa_id_admin2}) ---")
    print(f"Searching for revoke form: {revoke_form_admin2_pattern}")
    print(f"Form present in HTML: {is_form_admin2_present}")
    print(f"Expected: Form NOT present")
    if not is_form_admin2_present:
        print("Result: PASS")
    else:
        print("Result: FAIL")

    # Pattern for Scenario 2 (Admin viewing Expert - testexpert)
    # Expected: Form IS present
    revoke_form_expert_pattern = f'action="/revoke_access/{pa_id_expert}"'
    is_form_expert_present = revoke_form_expert_pattern in html_content
    print(f"\n--- Scenario 2: Admin (current_user) viewing Expert (testexpert, PA_ID: {pa_id_expert}) ---")
    print(f"Searching for revoke form: {revoke_form_expert_pattern}")
    print(f"Form present in HTML: {is_form_expert_present}")
    print(f"Expected: Form IS present")
    if is_form_expert_present:
        print("Result: PASS")
    else:
        print("Result: FAIL")

    # Pattern for Scenario 3 (Admin viewing their own access - testadmin)
    # Expected: Form IS present
    revoke_form_admin1_self_pattern = f'action="/revoke_access/{pa_id_admin1_self}"'
    is_form_admin1_self_present = revoke_form_admin1_self_pattern in html_content
    print(f"\n--- Scenario 3: Admin (current_user) viewing their own access (testadmin, PA_ID: {pa_id_admin1_self}) ---")
    print(f"Searching for revoke form: {revoke_form_admin1_self_pattern}")
    print(f"Form present in HTML: {is_form_admin1_self_present}")
    print(f"Expected: Form IS present")
    if is_form_admin1_self_present:
        print("Result: PASS")
    else:
        print("Result: FAIL")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python analyze_html.py <html_file_path> <pa_id_admin1_self> <pa_id_admin2> <pa_id_expert>")
        sys.exit(1)

    html_file = sys.argv[1]
    try:
        arg_pa_id_admin1_self = int(sys.argv[2])
        arg_pa_id_admin2 = int(sys.argv[3])
        arg_pa_id_expert = int(sys.argv[4])
    except ValueError:
        print("Error: ProjectAccess IDs must be integers.")
        sys.exit(1)

    analyze(html_file, arg_pa_id_admin1_self, arg_pa_id_admin2, arg_pa_id_expert)
