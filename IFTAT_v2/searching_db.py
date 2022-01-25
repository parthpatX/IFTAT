#!/usr/bin/env python3

#####################################################################
# Copyright (C) 2020-2021 Intel Corporation
# @author Parth Pathak
# Usage: Analyse the gtraces that are produced while running regtest
#####################################################################

# Importing the required modules
import pandas as pd
import create_db as db
from bisect import bisect_left, bisect_right

# Creating the dataframe of required CSVs
codebase_df = pd.read_csv("db.csv")
stdout_df = pd.read_csv("stdout_db1.csv")
#stdout_df = pd.read_csv("traces.csv")

# Fetching TRACE_NAME and LINE_NO from the corresponding dataframes and converting them to lists
trace_name = stdout_df['TRACE_NAME'].to_list()
expected_line_no = stdout_df['LINE_NO'].to_list()
#trace_info = codebase_df['TRACE_INFO'].to_list()

# Looping through all the traces from stdout file and Searching them on db
for i in range(len(trace_name)):
    # Storing the current trace name and it's corresponding line number for printing and querying
    name = trace_name[i] 
    line = expected_line_no[i]
    #info = trace_info[i].strip()

    # Printing current name and line number
    print('{:<42s}{:>10d}'.format(name, line))

    ''' 
    Method 01: Using Manual Offset:
    ###############################
    # Creating dataframe from db for fresh querying for Case I: __LINE__ 
    codebase_df = pd.read_csv("db.csv") 
    
    # Querying dataframe with current name and line number using manual offset of [-50, +50]
    codebase_df.query('TRACE_NAME == @name and @line - 50 <= LINE_NO <= @line + 50', inplace = True)

    # Printing the results
    print(codebase_df)

    # Creating dataframe from db for fresh querying for Case II: non __LINE__ 
    codebase_df = pd.read_csv("db.csv")

    # Querying dataframe with current name and non __LINE__
    codebase_df.query('TRACE_NAME == @name and TRACE_INFO != "__LINE__"', inplace = True)

    # Printing the results
    print(codebase_df)
    ###############################
    '''

    '''
    Method 02: Using Efficient Binary Search (Bisect Left Approach):
    '''

    # Creating dataframe from db for fresh querying for Case I: __LINE__
    codebase_df = pd.read_csv("db.csv")

    # Querying dataframe with current name and line number to get all results for case I
    codebase_df.query('TRACE_NAME == @name and TRACE_INFO == "__LINE__"', inplace = True)
    #print(codebase_df)
    # Fetching the LINE_NO column into actual_line_no
    actual_line_no = codebase_df['LINE_NO'].to_list()

    # Sorting the actual line number's list to apply Binary Search method
    actual_line_no.sort()

    # Checking if actual_line_no is empty, i.e., Case II: non __LINE__
    if(not actual_line_no):

        # Printing the results where there is a match for current name and Case II: non __LINE__
        codebase_df = pd.read_csv("db.csv")
        codebase_df.query('TRACE_NAME == @name and TRACE_INFO != "__LINE__"', inplace = True)
        print(codebase_df)

        #print(actual_line_no)
        #print(l,r)
        #print("NOT FOUND")
    else:

        # If the current line number is lesser than or equal to the actual line number at 0th index then returning the line number at 0th index
        if(line <= actual_line_no[0]):
            l = actual_line_no[0]
            r = actual_line_no[0]

            # Querying the dataframe within the obtained range to get the final results
            codebase_df.query('@l <= LINE_NO <= @r', inplace = True)
            print(codebase_df)

        # If the current line number is greater than or equal to the actual line number at last index then returning the line number at last index
        elif(line >= actual_line_no[len(actual_line_no)-1]):
            l = actual_line_no[len(actual_line_no)-1]
            r = actual_line_no[len(actual_line_no)-1]

            # Querying the dataframe within the obtained range to get the final results
            codebase_df.query('@l <= LINE_NO <= @r', inplace = True)
            print(codebase_df)

        # Otherwise applying Binary Search (Bisect Left method) to find the accurate range 
        else:
            l0 = actual_line_no[bisect_left(actual_line_no, line)-1]
            l = actual_line_no[bisect_left(actual_line_no, line)]
            r = actual_line_no[bisect_right(actual_line_no, line)]
            diff_l = []

            diff_l.append(abs(line-l0))
            diff_l.append(abs(line-l))
            #diff_r.append(abs(line-r))
            #diff_r.append(abs(line-r0))
            min_l = min(diff_l)

            index_min_l = diff_l.index(min_l)

            #print(index_min_l,index_min_r)
            if(index_min_l==0):
                l = l0
            l_diff = abs(l-line)
            r_diff = abs(r-line)

            if(l_diff < r_diff):
                # Querying the dataframe within the obtained range to get the final results
                codebase_df.query('LINE_NO == @l', inplace = True)
                print(codebase_df)

            elif(l_diff == r_diff):
                # Querying the dataframe within the obtained range to get the final results
                codebase_df.query('@l <= LINE_NO <= @r', inplace = True)
                print(codebase_df)

            else:
                # Querying the dataframe within the obtained range to get the final results
                codebase_df.query('LINE_NO == @r', inplace = True)
                print(codebase_df)
        #print(actual_line_no)
        #print(l,r)

        
        
    
    print(140*'=')

print("Query executed successfully!! :)")
