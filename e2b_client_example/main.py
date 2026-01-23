# main.py
from dotenv import load_dotenv
load_dotenv()
from e2b_code_interpreter import Sandbox




def create_exec_sandbox():
    sbx = Sandbox.create()
    execution = sbx.run_code("print('hello world')")
    print(execution)

if __name__ == "__main__":
    create_exec_sandbox()
