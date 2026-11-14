# Run COMMAND [ARG]... in a new pseudo-terminal, as its controlling terminal,
# type KEYS there (Python bytes escapes, e.g. '\x03' for Ctrl-C) one at a
# time after 0.5 s, 0.3 s apart, and print the exit status of COMMAND.
#
# Usage: terminal.py KEYS COMMAND [ARG]...
import os, pty, sys, time

keys = sys.argv[1].encode().decode("unicode_escape").encode("latin-1")
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[2], sys.argv[2:])
time.sleep(0.5)
for k in keys:
    os.write(fd, bytes([k]))
    time.sleep(0.3)
try:
    while os.read(fd, 4096):
        pass
except OSError:
    pass
print(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
