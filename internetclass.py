import pandas as pd
import subprocess


def linux_command(arg2='execute'):
    cmd = 'gradle'
    
    print('Starting CICFlowMeter.....')
    temp = subprocess.Popen([cmd,arg2], stdout=subprocess.PIPE)
    output = str(temp.communicate())
    print('CICFlowMeter is running')
    # A variable to store the output
    res = []

    # iterating through the output line by line
    for line in output:
        res.append(line)

    # print the output
    for i in range(1, len(res)):
        print(res[i])
    return res


linux_command()
