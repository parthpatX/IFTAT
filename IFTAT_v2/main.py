#!/usr/bin/env python3

#####################################################################
# Copyright (C) 2020-2021 Intel Corporation
# @author Parth Pathak
# Usage: Analyse the gtraces that are produced while running regtest
#####################################################################

# Importing the required modules
import create_db as db

# Creating object of class ProcessTraces for searching in specified path
processTraces = db.ProcessTraces('.')

# Finding the files specified within current path
txt_file_names = processTraces.find_files('stdout.txt')

# Opening of matched files
txt_files = processTraces.open_files(txt_file_names)

# Reading lines from each of the files
txt_lines = processTraces.lines_from_files(txt_files)

# Printing the stats from stdout and creating databases
processTraces.print_stats(txt_lines)
