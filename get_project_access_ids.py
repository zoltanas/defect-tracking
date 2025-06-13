import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'myapp.db')
PROJECT_NAME = "Comprehensive Test Project"

def get_ids():
    pa_id_admin1_self = None
    pa_id_admin2 = None
    pa_id_expert = None

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Get project_id
        cursor.execute("SELECT id FROM projects WHERE name = ?", (PROJECT_NAME,))
        project_row = cursor.fetchone()
        if not project_row:
            print(f"ERROR: Project '{PROJECT_NAME}' not found.")
            return None, None, None
        project_id = project_row[0]

        # Get user IDs
        cursor.execute("SELECT id FROM users WHERE username = 'testadmin'")
        user_admin1_row = cursor.fetchone()
        user_admin1_id = user_admin1_row[0] if user_admin1_row else None

        cursor.execute("SELECT id FROM users WHERE username = 'testadmin2'")
        user_admin2_row = cursor.fetchone()
        user_admin2_id = user_admin2_row[0] if user_admin2_row else None

        cursor.execute("SELECT id FROM users WHERE username = 'testexpert'")
        user_expert_row = cursor.fetchone()
        user_expert_id = user_expert_row[0] if user_expert_row else None

        if not all([user_admin1_id, user_admin2_id, user_expert_id]):
            print(f"ERROR: One or more users (testadmin, testadmin2, testexpert) not found.")
            return None, None, None

        # Get ProjectAccess IDs
        cursor.execute("SELECT id FROM project_access WHERE user_id = ? AND project_id = ?", (user_admin1_id, project_id))
        pa_admin1_self_row = cursor.fetchone()
        pa_id_admin1_self = pa_admin1_self_row[0] if pa_admin1_self_row else None

        cursor.execute("SELECT id FROM project_access WHERE user_id = ? AND project_id = ?", (user_admin2_id, project_id))
        pa_admin2_row = cursor.fetchone()
        pa_id_admin2 = pa_admin2_row[0] if pa_admin2_row else None

        cursor.execute("SELECT id FROM project_access WHERE user_id = ? AND project_id = ?", (user_expert_id, project_id))
        pa_expert_row = cursor.fetchone()
        pa_id_expert = pa_expert_row[0] if pa_expert_row else None

        conn.close()

        if not all([pa_id_admin1_self, pa_id_admin2, pa_id_expert]):
            print(f"ERROR: Could not retrieve all ProjectAccess IDs. Make sure setup was complete.")
            print(f"Debug Info: project_id={project_id}, user_admin1_id={user_admin1_id}, user_admin2_id={user_admin2_id}, user_expert_id={user_expert_id}")
            print(f"Retrieved PA IDs: self={pa_id_admin1_self}, admin2={pa_id_admin2}, expert={pa_id_expert}")


        return pa_id_admin1_self, pa_id_admin2, pa_id_expert

    except Exception as e:
        print(f"Error querying database: {e}")
        return None, None, None

if __name__ == "__main__":
    # These PA_IDs were determined from the previous successful test run's setup phase.
    # The setup_and_test.py script ensures these users and their accesses are created.
    # testadmin is user_id 1 (typically, by flask-login default or first user)
    # Comprehensive Test Project is project_id 1
    # testadmin2 is user_id 3
    # testexpert is user_id 4
    # ProjectAccess for testadmin to project 1 would be PA_ID 1 or 2
    # ProjectAccess for testadmin2 to project 1 was PA_ID 3 in previous run
    # ProjectAccess for testexpert to project 1 was PA_ID 4 in previous run

    # The get_ids() function dynamically queries them to be sure.
    id_admin1_self, id_admin2, id_expert = get_ids()

    if id_admin1_self and id_admin2 and id_expert:
        print(f"PA_ID_ADMIN1_SELF:{id_admin1_self}")
        print(f"PA_ID_ADMIN2:{id_admin2}")
        print(f"PA_ID_EXPERT:{id_expert}")
    else:
        print("Failed to retrieve one or more ProjectAccess IDs.")
