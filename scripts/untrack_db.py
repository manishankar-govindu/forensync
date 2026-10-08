import subprocess

res = subprocess.run(["git", "rm", "--cached", "-f", "backend/instance/forensync.db"], capture_output=True, text=True)
print("Result stdout:", res.stdout)
print("Result stderr:", res.stderr)
