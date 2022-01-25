#!/usr/bin/env python3

#####################################################################
# Copyright (C) 2020-2021 Intel Corporation
# @author Parth Pathak
# Usage: Analyse the gtraces that are produced while running regtest
#####################################################################

# Importing the required modules
import os
import sys
import urllib.request
import fnmatch
import re
import pandas as pd
from bisect import bisect_left, bisect_right


class ProcessTraces:
    """
    A class used to process traces and creating database

    ...

    Attributes
    ----------
    top_level_dir : Any
        Top level directory containing stdout files
    pattern : Any
        Pattern used for searching stdout files
    filenames : Any
        Names of files that matches with pattern
    files : Any
        Path of files that are matched with pattern
    lines : Any
        Lines of files that are matched with pattern

    Methods
    -------
    find_files(pattern)
        Returning the files specified within current path that matches the pattern
    open_files(filenames)
        Opening of files mentioned in parameter
    lines_from_files(files)
        Returning lines from each of the files
    print_stats(lines)
        Printing the stats from stdout, i.e., number of traces, errors, and source_files
        creating databases stdout_db, trace_db, and db 
    """

    def __init__(self, top_level_dir):
        """
        Parameters
        ----------
        top_level_dir : Any
            Top level directory containing stdout files
        """
        self.top_level_dir = top_level_dir
        
    def find_files(self, pattern):
        """
        Returning the files specified within current path that matches the pattern

        Parameters
        ----------
        pattern : Any
            Pattern used for searching stdout files
        """
        # Walking through the top_level_dir and returning filepath, sub-directories, and files
        for path, dirlist, filelist in os.walk(self.top_level_dir):
            # Looping through all the files in filelist and returning files which match the pattern
            for name in fnmatch.filter(filelist, pattern):
                # Returning path and name of the file
                yield os.path.join(path, name)

    def open_files(self, filenames):
        """
        Returning the files specified within current path that matches the pattern

        Parameters
        ----------
        filenames : Any
            Opening of files mentioned in parameter
        """
        # Looping through all files in filenames
        for name in filenames:
            # Opening and  returning files
            yield open(name, 'r', encoding='utf-8')

    def lines_from_files(self, files):
        """
        Returning lines from each of the files

        Parameters
        ----------
        files : Any
            Path of files that are matched with pattern
        """
        # Looping through all files
        for f in files:
            # Looping through lines of files
            for line in f:
                # Returning each line
                yield line

    def create_stdoutdb(self, lines):

        num_of_errors = 0 # To keep the total number of errors in stdout
        errors = re.compile('(_ERROR)') # Pattern regular expression to match "_ERROR" string
        traces = [] # TO keep traces of stdout
        t, l = [], [] # Temporary storing trace names and line numbers
        firmware_v = ''
        quartuskit_v = ''
        flag1 = 0
        flag2 = 0
        # Looping through the lines to find traces, i.e., TRACE lines starts with '['
        for line in lines:
            if line.__contains__('firmware'):
                firmware_v = line[line.index('firmware'):-1]

            if line.__contains__('/quartuskit/') and flag1 == 0:
                quartuskit_v = line[line.index('/quartuskit/'):-1]
                flag1 = 1 

            if line.__contains__('acds_version') and flag2 == 0:
                quartuskit_v = line[line.index('acds_version'):-1]
                flag2 = 1

            if line.startswith('['):
                traces.append(line[6:].split()) #Appending TRACE_NAME to traces list
        
        #print(traces)
        
        error = [] # Storing error traces from stdout
        line_num = [] # Storing line number of corresponding error traces from stdout
        #hexa = []

        print("\nCreating stdout_db.csv...")
        # Looping through all traces from traces list to create a database traces.csv
        for i in range(len(traces)):
            t.append(traces[i][0]) # Storing trace names to t list
            l.append(traces[i][1]) # Storing line number corresponding to trace names in l list
            if errors.search(traces[i][0]):
                num_of_errors += 1  # Counter to keep the track of number of errored traces
                
                # Fetching the previous trace to the errored trace along with it's line number
                error.append(traces[i-1][0])
                line_num.append(int(traces[i-1][1]))
                #hexa.append(hex(int(traces[i-1][2][1:-1], 16)))

                # Fetching the current errored trace along with it's line number
                error.append(traces[i][0])
                line_num.append(int(traces[i][1]))
                #hexa.append(hex(int(traces[i][2][1:-1], 16)))

                # Fetching the next trace to the errored trace along with it's line number
                if(i!=len(traces)-1): # Checking if it is last trace then just continue otherwise fetch the next trace info
                    error.append(traces[i+1][0])
                    line_num.append(int(traces[i+1][1]))
                    #hexa.append(hex(int(traces[i+1][2][1:-1], 16)))

        # Creating dataframe from TRACE_NAME and LINE_NO that we fetched for errored traces and it's corresponding line number from stdout
        stdout_df = pd.DataFrame({'TRACE_NAME': error, 'LINE_NO': line_num})
        #print(trace_df)
        stdout_df.to_csv('stdout_db.csv')
        print("stdout_db.csv created!")

        print("\nCreating traces.csv...")

        # Creating dataframe from TRACE_NAME and LINE_NO that we fetched for every traces and it's corresponding line number from stdout
        t_df = pd.DataFrame({'TRACE_NAME': t, 'LINE_NO': l})
        t_df.to_csv('traces.csv')
        print("traces.csv created!")

       
        #for i in range(len(error)):
            #print ("{:<8} {:<15}".format(error[i],line_num[i]))
            #print(error[i], "\t\t\t\t", line_num[i])
            #print(error[i], line_num[i], hexa[i])

        #print("LINE# = ", line_num)
        #print("LINE# (HEX) = ", hexa)
        #print("TRACES = ", error)
        
        # Printing the total ERRORED TRACES and total TRACE LINES
        print("\n- Number of ERRORS =", num_of_errors)
        print("- Number of TRACE LINES =", len(traces))

        print("\nFirmware version = ", firmware_v)
        print("Quartuskit version = ", quartuskit_v[1:-69]) if flag1 == 1 else print("Quartuskit version = ", quartuskit_v[15:])

    def print_stats(self, lines):
        
        """
        Printing the stats from stdout, i.e., number of traces, errors, and source_files
        creating databases stdout_db, trace_db, and db 

        Parameters
        ----------
        lines : Any
            Lines of files that are matched with pattern
        """
        """   
        num_of_errors = 0 # To keep the total number of errors in stdout
        errors = re.compile('(_ERROR)') # Pattern regular expression to match "_ERROR" string
        traces = [] # TO keep traces of stdout
        t, l = [], [] # Temporary storing trace names and line numbers
        
        # Looping through the lines to find traces, i.e., TRACE lines starts with '['
        for line in lines:
            if line.startswith('['):
                traces.append(line[6:].split()) #Appending TRACE_NAME to traces list
        
        #print(traces)
        
        error = [] # Storing error traces from stdout
        line_num = [] # Storing line number of corresponding error traces from stdout
        #hexa = []

        print("\nCreating stdout_db.csv...")
        # Looping through all traces from traces list to create a database traces.csv
        for i in range(len(traces)):
            t.append(traces[i][0]) # Storing trace names to t list
            l.append(traces[i][1]) # Storing line number corresponding to trace names in l list
            if errors.search(traces[i][0]):
                num_of_errors += 1  # Counter to keep the track of number of errored traces
                
                # Fetching the previous trace to the errored trace along with it's line number
                error.append(traces[i-1][0])
                line_num.append(int(traces[i-1][1]))
                #hexa.append(hex(int(traces[i-1][2][1:-1], 16)))

                # Fetching the current errored trace along with it's line number
                error.append(traces[i][0])
                line_num.append(int(traces[i][1]))
                #hexa.append(hex(int(traces[i][2][1:-1], 16)))

                # Fetching the next trace to the errored trace along with it's line number
                if(i!=len(traces)-1): # Checking if it is last trace then just continue otherwise fetch the next trace info
                    error.append(traces[i+1][0])
                    line_num.append(int(traces[i+1][1]))
                    #hexa.append(hex(int(traces[i+1][2][1:-1], 16)))

        # Creating dataframe from TRACE_NAME and LINE_NO that we fetched for errored traces and it's corresponding line number from stdout
        stdout_df = pd.DataFrame({'TRACE_NAME': error, 'LINE_NO': line_num})
        #print(trace_df)
        stdout_df.to_csv('stdout_db.csv')
        print("stdout_db.csv created!")

        print("\nCreating traces.csv...")

        # Creating dataframe from TRACE_NAME and LINE_NO that we fetched for every traces and it's corresponding line number from stdout
        t_df = pd.DataFrame({'TRACE_NAME': t, 'LINE_NO': l})
        t_df.to_csv('traces.csv')
        print("traces.csv created!")

       
        #for i in range(len(error)):
            #print ("{:<8} {:<15}".format(error[i],line_num[i]))
            #print(error[i], "\t\t\t\t", line_num[i])
            #print(error[i], line_num[i], hexa[i])

        #print("LINE# = ", line_num)
        #print("LINE# (HEX) = ", hexa)
        #print("TRACES = ", error)
        
        # Printing the total ERRORED TRACES and total TRACE LINES
        print("\n- Number of ERRORS =", num_of_errors)
        print("- Number of TRACE LINES =", len(traces))
        """

        #walk_dir = 'C:\\Users\\parthpat\\OneDrive - Intel Corporation\\Desktop\\IFTAT\\demo'
        
        walk_dir = 'C:\\Users\\parthpat\\firmware' # Path to firmware code base
        sdm_trace_dir = 'C:\\Users\parthpat\\firmware\\sdm\\app\\common\\inc\\sdm_trace.h' # Path to sdm_trace.h file within firmware source code
        
        # If the file path contains these we dont want them
        # eg. C:\\Users\\parthpat\\firmware\\test will be ignored
        exclusions = [".github", "artifactory", ".gitattributes", ".gitignore", ".gitlab-ci.yml", "coverity.mk", "LICENSE", "Makefile", "symlink_hooks.sh"]
        
        # Array to store all our file paths
        file_paths = []
        # Iterate file tree
        for root, sub_dirs, file_names in os.walk(walk_dir):
            
            # Iterate the file names in the directory
            for file_name in file_names:
                
                # We only are interested in C Files
                if file_name.endswith(".c"):
                
                    # If the file path doesn't have 
                    #   anything from the exclusion list
                    if not any(exclusion in root for exclusion in exclusions):
                        file_paths.append(os.path.join(root, file_name))

        # Number of C source files to be searched
        print('- Number of SOURCE FILES =', len(file_paths))
        
        #occurances = []
        file_path_list = []         # List of file paths that contains sdm_trace.h traces in codebase
        string_list = []            # List of matched trace names from sdm_trace.h in codebase
        no_list = []                # List of line numbers corresponding to matched traces from sdm_trace.h in codebase
        trace_macro_list = []       # List of trace macros of matched trace from sdm_trace.h in codebse
        trace_info_list = []        # List of trace info, i.e., 2nd parameter from the corresponding macros
        func_list = []              # List that maintains every function's signature present in codebase
        func_line_list = []         # List containing the line number of correspoding functions
        index = []                  # List of function signature that contains the matched traces from sdm_traces.h in codebase
        #func_line_list_tmp = []
        sdm_traces = []             # List maintaining every traces of sdm_traces.h

        print("\nCreating sdm_traces.csv...")
        # Looping through sdm_traces.h directory to fetch each trace
        
        with open(sdm_trace_dir, 'r', encoding='utf8', errors='ignore' ) as f:
            # Reading and splitting each line with '\n'
            data = f.read().split("\n")
            
            # Enumerating each lines to get the trace name string
            for i, t in enumerate(data):
                
                # Checking if it's not an empy line
                if t.__len__() != 0:    
                    
                    # Checking to ensure that trace names are starting with upper case and containing underscore (_)
                    if t.strip()[0].isupper() and t.__contains__('_'):
                        # If trace name contains eqaul (=) sign then discarding that sign
                        t = t.strip().split('=')[0] if t.__contains__('=') else t
                        
                        # Removing the comma (,) at the end of traces if present
                        t = t.strip()[:-1] if t.strip().endswith(',') else t.strip()   

                        # Appending the resultant trace name
                        sdm_traces.append(t)

        # Creating dataframe from sdm traces collected above
        sdm_traces_df = pd.DataFrame({'SDM_TRACES': sdm_traces})
        sdm_traces_df.to_csv('sdm_traces.csv')
        print("sdm_traces.csv created!")

        # Reading keywords from txt file and storing them in list
        with open('C:\\Users\\parthpat\\OneDrive - Intel Corporation\\Desktop\\IFTAT_v2\\keywords.txt', 'r', encoding='utf8', errors='ignore' ) as f:
            keywords = f.read().split("\n")

        print("\nCreating db.csv...")

        # Iterate previously collected file paths
        for file_path in file_paths:

            # Created temporary function name and corresponding line number lists
            func_line_list_tmp = [] 
            func_list_tmp = []

            # Open the file as read only ignoring unknown chars
            with open(file_path, 'r', encoding='utf8', errors='ignore' ) as f:
                
                # Reading and splitting lines of each file from file_path
                contents = f.read()
                lines = contents.split("\n")

                # Enumerating through lines of files for fetching all function's signatures
                for p, k in enumerate(lines):
                    
                    # Checking if the line starts with specific chars
                    if not (k.startswith(' ') or k.startswith('\t') or k.lstrip().startswith('#') or k.lstrip().startswith('//') or k.endswith(';') or k.__contains__('{}')):
                        
                        # Checking to ensure that line number starts with specific keyword that are matched with keyword list
                        if any(k.startswith(x) for x in keywords) and k.__contains__('('):
                            func_line_list.append(p+1)                  # Appending the required function's line numbers
                            func_list.append(k)                         # Appending it's corresponding function signatures
                            func_line_list_tmp.append(p+1)              # Appending the required function's line numbers for temporary
                            k = lines[p-1] if k.startswith('(') else k  # If any line starts with left bracket ('(') then previous line will be the required function
                            #k = k.split(" ")[1][1:] if k.__contains__(' ') else k[1:] 
                            func_list_tmp.append(k)                     # Appending the required function's signature for temporary 
                #print(func_line_list_tmp)

                # For each trace present in sdm_traces
                for string in sdm_traces:
                    
                    # Adding delimeters '(' and ',' to match with the code line
                    #countError = contents.count(string)
                    string = '('+string+','

                    # For each line of entire code base
                    for i, s in enumerate(lines):
                        
                        # If trace of sdm_traces.h present in any line
                        if string in s:
                            
                            # Splitting that line with '(' and getting the 0th element which is trace macro
                            trace_macro = s.split("(")[0]

                            # To get the trace info splitting the 1st element with ',' and fetch the string till last two chars
                            trace_info = s.strip().split(",")[1][:-2]
                            
                            # Keeping the track of current line number
                            no = i+1
                            
                            #if trace_macro.lstrip().find("//") == 0 or trace_macro.lstrip().find("/*") == 0:
                                #continue

                            # Creating seperate list for every components
                            file_path_list.append(file_path)                    # Appending current file path
                            string_list.append(string[1:-1])                    # Appending current trace name
                            no_list.append(no)                                  # Appending current line number
                            trace_macro_list.append(trace_macro.lstrip())       # Appending current macro name
                            trace_info_list.append(trace_info.strip())          # Appending current trace info
                            #print(func_line_list_tmp)
                            #id = bisect_left(func_line_list_tmp, no) - 1
                            #print(id)
                            #print(func_line_list_tmp[bisect_left(func_line_list_tmp, no) - 1])

                            # Using Binary Search (Bisect left method) to get required function which contains the current trace name
                            index.append(func_list_tmp[bisect_left(func_line_list_tmp, no) - 1])
                            #occurances.append([file_path, string[1:-1], str(no), trace_macro.lstrip()])
                
            
                    # If there is TRACES with ERROR in the file append it to 
                    #   the occurances array
                    #if countError > 0:
                        #occurances.append([file_path, string, str(countError), str(len(lines)), str(no), trace_macro.lstrip()])
                #index.clear()
                #for i in range(len(no_list)):
                #    index.append(bisect_left(func_line_list, no_list[i]) - 1)


        # Create an output csv string
        #outCSV = "\n".join([",".join(line) for line in occurances])

        # Write to file
        #with open("Outfile.csv", 'w+') as f:
        #    f.write(outCSV)
        #print(len(no))
        
        
        #func_df = pd.DataFrame({'FUNC_NAME': func_list, 'FUNC_LINE_NO': func_line_list})

        # Creating dataframe for codebase's db creation
        codebase_df = pd.DataFrame({'FILE_PATH': file_path_list, 'FUNC_NAME': index, 'TRACE_NAME': string_list, 'LINE_NO': no_list, 'TRACE_MACRO': trace_macro_list, 'TRACE_INFO': trace_info_list})
        codebase_df.index.name = 'ID' 
        #print(codebase_df)
        codebase_df.to_csv('db.csv')
        
        print("db.csv created!")
        #func_df.to_csv('func.csv')
        
        #print(len(func_list))
        #print(len(index))
        print("\nDatabases created successfully!! :)")

def searching_db():

    print(140*'=')
    # Creating the dataframe of required CSVs
    codebase_df = pd.read_csv("db.csv")
    stdout_df = pd.read_csv("stdout_db.csv")
    #stdout_df = pd.read_csv("traces.csv")

    ID = []
    FILE_PATH = []
    FUNC_NAME = []
    TRACE_NAME = []
    LINE_NO = []
    TRACE_MACRO = []
    TRACE_INFO = []

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
            ID.extend(codebase_df['ID'].to_list())
            FILE_PATH.extend(codebase_df['FILE_PATH'].to_list())
            FUNC_NAME.extend(codebase_df['FUNC_NAME'].to_list())
            TRACE_NAME.extend(codebase_df['TRACE_NAME'].to_list())
            LINE_NO.extend(codebase_df['LINE_NO'].to_list())
            TRACE_MACRO.extend(codebase_df['TRACE_MACRO'].to_list())
            TRACE_INFO.extend(codebase_df['TRACE_INFO'].to_list())
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
                ID.extend(codebase_df['ID'].to_list())
                FILE_PATH.extend(codebase_df['FILE_PATH'].to_list())
                FUNC_NAME.extend(codebase_df['FUNC_NAME'].to_list())
                TRACE_NAME.extend(codebase_df['TRACE_NAME'].to_list())
                LINE_NO.extend(codebase_df['LINE_NO'].to_list())
                TRACE_MACRO.extend(codebase_df['TRACE_MACRO'].to_list())
                TRACE_INFO.extend(codebase_df['TRACE_INFO'].to_list())
                print(codebase_df)

            # If the current line number is greater than or equal to the actual line number at last index then returning the line number at last index
            elif(line >= actual_line_no[len(actual_line_no)-1]):
                
                l = actual_line_no[len(actual_line_no)-1]
                r = actual_line_no[len(actual_line_no)-1]

                # Querying the dataframe within the obtained range to get the final results
                codebase_df.query('@l <= LINE_NO <= @r', inplace = True)
                ID.extend(codebase_df['ID'].to_list())
                FILE_PATH.extend(codebase_df['FILE_PATH'].to_list())
                FUNC_NAME.extend(codebase_df['FUNC_NAME'].to_list())
                TRACE_NAME.extend(codebase_df['TRACE_NAME'].to_list())
                LINE_NO.extend(codebase_df['LINE_NO'].to_list())
                TRACE_MACRO.extend(codebase_df['TRACE_MACRO'].to_list())
                TRACE_INFO.extend(codebase_df['TRACE_INFO'].to_list())
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
                    ID.extend(codebase_df['ID'].to_list())
                    FILE_PATH.extend(codebase_df['FILE_PATH'].to_list())
                    FUNC_NAME.extend(codebase_df['FUNC_NAME'].to_list())
                    TRACE_NAME.extend(codebase_df['TRACE_NAME'].to_list())
                    LINE_NO.extend(codebase_df['LINE_NO'].to_list())
                    TRACE_MACRO.extend(codebase_df['TRACE_MACRO'].to_list())
                    TRACE_INFO.extend(codebase_df['TRACE_INFO'].to_list())
                    print(codebase_df)

                elif(l_diff == r_diff):
                    # Querying the dataframe within the obtained range to get the final results
                    codebase_df.query('@l <= LINE_NO <= @r', inplace = True)
                    ID.extend(codebase_df['ID'].to_list())
                    FILE_PATH.extend(codebase_df['FILE_PATH'].to_list())
                    FUNC_NAME.extend(codebase_df['FUNC_NAME'].to_list())
                    TRACE_NAME.extend(codebase_df['TRACE_NAME'].to_list())
                    LINE_NO.extend(codebase_df['LINE_NO'].to_list())
                    TRACE_MACRO.extend(codebase_df['TRACE_MACRO'].to_list())
                    TRACE_INFO.extend(codebase_df['TRACE_INFO'].to_list())
                    print(codebase_df)

                else:
                    # Querying the dataframe within the obtained range to get the final results
                    codebase_df.query('LINE_NO == @r', inplace = True)
                    ID.extend(codebase_df['ID'].to_list())
                    FILE_PATH.extend(codebase_df['FILE_PATH'].to_list())
                    FUNC_NAME.extend(codebase_df['FUNC_NAME'].to_list())
                    TRACE_NAME.extend(codebase_df['TRACE_NAME'].to_list())
                    LINE_NO.extend(codebase_df['LINE_NO'].to_list())
                    TRACE_MACRO.extend(codebase_df['TRACE_MACRO'].to_list())
                    TRACE_INFO.extend(codebase_df['TRACE_INFO'].to_list())
                    print(codebase_df)
            #print(actual_line_no)
            #print(l,r)

        print(140*'=')
    
    result = pd.DataFrame({'FILE_PATH': FILE_PATH, 'FUNC_NAME': FUNC_NAME, 'TRACE_NAME': TRACE_NAME, 'LINE_NO': LINE_NO, 'TRACE_MACRO': TRACE_MACRO, 'TRACE_INFO': TRACE_INFO})
    result.to_csv('report.csv')
    print("Query executed successfully!! :)")


if __name__ == "__main__":
    
    if (len(sys.argv) < 2):

        print("Too low parameters to execute!!")
        exit()

    elif (len(sys.argv) > 2):
        
        print("Too many parameters to execute!!")
        exit()

    else:

        target_url = sys.argv[-1]
        try:
            data = urllib.request.urlopen(target_url)
            #fn = sys.argv[-1]
            content = []
            stdout_file = 'stdout_' + target_url.split('/')[-2] + '.txt'
            with open(stdout_file, 'w') as f:
                for line in data:
                    decoded_line = line.decode("utf-8")
                    f.write(decoded_line)
                    content.append(decoded_line)

            #filename = fn.split("/")[-1]
            choice = input("Whether or not wants to create database (Y/N)?: ")
                
            #if(os.path.exists('./' + filename) == False):

            if (choice == 'Y'):

                # Creating object of class ProcessTraces for searching in specified path
                processTraces = ProcessTraces('.')

                # Finding the files specified within current path
                txt_file_names = processTraces.find_files(stdout_file)

                # Opening of matched files
                txt_files = processTraces.open_files(txt_file_names)

                # Reading lines from each of the files
                txt_lines = processTraces.lines_from_files(txt_files)

                processTraces.create_stdoutdb(txt_lines)

                # Printing the stats from stdout and creating databases
                processTraces.print_stats(txt_lines)

                searching_db()
                
            elif (choice == 'N' and (os.path.exists('./sdm_traces.csv') == False or os.path.exists('./db.csv') == False or os.path.exists('./stdout_db.csv') == False)):

                # Creating object of class ProcessTraces for searching in specified path
                processTraces = ProcessTraces('.')

                # Finding the files specified within current path
                txt_file_names = processTraces.find_files(stdout_file)

                # Opening of matched files
                txt_files = processTraces.open_files(txt_file_names)

                # Reading lines from each of the files
                txt_lines = processTraces.lines_from_files(txt_files)

                processTraces.create_stdoutdb(txt_lines)

                # Printing the stats from stdout and creating databases
                processTraces.print_stats(txt_lines)

                searching_db()
                
            else:
                    
                # Creating object of class ProcessTraces for searching in specified path
                processTraces = ProcessTraces('.')

                # Finding the files specified within current path
                txt_file_names = processTraces.find_files(stdout_file)

                # Opening of matched files
                txt_files = processTraces.open_files(txt_file_names)

                # Reading lines from each of the files
                txt_lines = processTraces.lines_from_files(txt_files)

                processTraces.create_stdoutdb(txt_lines)
                    
                searching_db()         
        
        except:
            print("File does not exist!!")





