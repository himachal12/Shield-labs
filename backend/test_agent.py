from app.agents.code_parser import CodeParserAgent

agent = CodeParserAgent()

sample_code = """
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)

class UserRepository:
    def find_by_id(self, user_id):
        pass
"""

result = agent.analyze("test_temp.py", sample_code)
print("STRUCTURAL ANALYSIS:")
print(result)