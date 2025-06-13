import sys

def analyze(html_file_path, pa_id_admin2_project_admin, pa_id_admin3_project_expert, pa_id_expertuser_project_expert):
    try:
        with open(html_file_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
    except FileNotFoundError:
        print(f"ERROR: HTML file '{html_file_path}' not found.")
        return

    # --- Scenario 1: testadmin2 (global admin, project admin) ---
    # Expected: Form IS HIDDEN
    pattern_s1 = f'action="/revoke_access/{pa_id_admin2_project_admin}"'
    is_form_s1_present = pattern_s1 in html_content
    print(f"\n--- Scenario 1: testadmin2 (Global Admin, Project Admin, PA_ID: {pa_id_admin2_project_admin}) ---")
    print(f"Searching for revoke form: {pattern_s1}")
    print(f"Form present in HTML: {is_form_s1_present}")
    print(f"Expected: Form IS HIDDEN (False)")
    if not is_form_s1_present:
        print("Result: PASS")
    else:
        print("Result: FAIL")

    # --- Scenario 2: testadmin3 (global admin, project expert) ---
    # Expected: Form IS VISIBLE
    pattern_s2 = f'action="/revoke_access/{pa_id_admin3_project_expert}"'
    is_form_s2_present = pattern_s2 in html_content
    print(f"\n--- Scenario 2: testadmin3 (Global Admin, Project Expert, PA_ID: {pa_id_admin3_project_expert}) ---")
    print(f"Searching for revoke form: {pattern_s2}")
    print(f"Form present in HTML: {is_form_s2_present}")
    print(f"Expected: Form IS VISIBLE (True)")
    if is_form_s2_present:
        print("Result: PASS")
    else:
        print("Result: FAIL")

    # --- Scenario 3: testexpertuser (global expert, project expert) ---
    # Expected: Form IS VISIBLE
    pattern_s3 = f'action="/revoke_access/{pa_id_expertuser_project_expert}"'
    is_form_s3_present = pattern_s3 in html_content
    print(f"\n--- Scenario 3: testexpertuser (Global Expert, Project Expert, PA_ID: {pa_id_expertuser_project_expert}) ---")
    print(f"Searching for revoke form: {pattern_s3}")
    print(f"Form present in HTML: {is_form_s3_present}")
    print(f"Expected: Form IS VISIBLE (True)")
    if is_form_s3_present:
        print("Result: PASS")
    else:
        print("Result: FAIL")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python analyze_html_specific.py <html_file_path> <pa_id_s1> <pa_id_s2> <pa_id_s3>")
        sys.exit(1)

    html_file = sys.argv[1]
    try:
        arg_pa_id_s1 = int(sys.argv[2]) # ADMIN2_PROJECT_ADMIN
        arg_pa_id_s2 = int(sys.argv[3]) # ADMIN3_PROJECT_EXPERT
        arg_pa_id_s3 = int(sys.argv[4]) # EXPERTUSER_PROJECT_EXPERT
    except ValueError:
        print("Error: ProjectAccess IDs must be integers.")
        sys.exit(1)

    analyze(html_file, arg_pa_id_s1, arg_pa_id_s2, arg_pa_id_s3)
