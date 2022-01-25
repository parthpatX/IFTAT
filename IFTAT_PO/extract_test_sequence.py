#!/usr/bin/env python3

#####################################################################
# Copyright (C) 2020-2021 Intel Corporation
# @author Parth Pathak, Faridabi Shaikh
# Usage: Extract the test sequence from FM71_PO
#####################################################################

# Importing the required modules
import sys
import urllib.request

out_file = ''

def system_console(content):
    
    with open(out_file, 'a+') as f:
        f.write("\nSYSTEM CONSOLE COMMANDS:\n\n")
        for i in range(len(content)):
            
            if (content[i].__contains__("SET :")):
                f.write(content[i][37:])
            if (content[i].__contains__("GET :") and not content[i].__contains__("CONFIG STATUS")):
                f.write(content[i][37:])
            if (content[i].__contains__("GET :") and content[i].__contains__("CONFIG STATUS")):
                #j = i
                while (not content[i].__contains__("#")):
                    f.write(content[i][37:])
                    i += 1
                
            if (content[i].__contains__("PYSV INFO:")):
                f.write(content[i][37:])
            

if __name__ == "__main__":
    
    if (len(sys.argv) < 2):

        print("Too low parameters to execute!!")
        exit()

    elif (len(sys.argv) > 2):
        
        print("Too many parameters to execute!!")
        exit()

    else:

        target_url = sys.argv[-1]
        data = urllib.request.urlopen(target_url)
        flag = 0
        content = []
        out_file = 'report_' + target_url.split('/')[-2] + '.txt'
        for line in data:
            decoded_line = line.decode("utf-8")
            content.append(decoded_line)
                
        with open(out_file, 'w') as f:
            for i in range(len(content)):
                if (content[i].__contains__("Register to Pert as pass succeeded.") and flag == 0):
                    f.write("\nTEST STATUS: Passed\n")
                    flag = 1
                
                if (content[i].__contains__("Info: Command: quartus_pgm")):
                    f.write(content[i][15:])

                if (content[i].__contains__("Info: Using INI") and content[i-1].__contains__("Info: Command: quartus_pgm")):
                    f.write("\t|___ INI FILE:" + content[i][20:])

                if (content[i].__contains__("Quartus Prime Programmer was")):
                    f.write("\t\t\t|___ STATUS: " + content[i] + "\n")

                if (content[i].__contains__("Info: Command: quartus_pfg")):
                    f.write(content[i][15:])

                if (content[i].__contains__("Info: Using INI") and content[i-1].__contains__("Info: Command: quartus_pfg")):
                    f.write("\t|___ INI FILE:" + content[i][20:])

                if (content[i].__contains__("Quartus Prime Programming File Generator was")):
                    f.write("\t\t\t|___ STATUS: " + content[i] + "\n")
        
                if (content[i].__contains__("{ REGTEST_REPOSITORY }")):
                    f.write("REGTEST_REPOSITORY:" + content[i][42:] + "\n")

            if (flag == 0):
                f.write("TEST STATUS: Failed\n")
                #print(decoded_line)
        
        system_console(content)